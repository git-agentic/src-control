//! Users, organizations and tokens: the queries every route and the admin CLI
//! share. No caching: every call reads the database, so an `admin` change is
//! visible to a running `serve` at once.

use crate::scope;
use rusqlite::{params, Connection, OptionalExtension, Row};
use scl_crypto::{generate_token, hash_token};

/// A user or an organization.
#[derive(Clone, Debug)]
pub struct User {
    pub id: i64,
    pub login: String,
    pub is_org: bool,
    pub login_name: String,
    pub full_name: String,
    pub email: String,
    pub description: String,
    pub website: String,
    pub location: String,
    pub password_hash: String,
    pub must_change_password: bool,
    pub is_admin: bool,
    pub visibility: String,
    pub created: i64,
}

const USER_COLS: &str = "id, login, kind, login_name, full_name, email, description, website, \
     location, password_hash, must_change_password, is_admin, visibility, created_unix";

fn user_row(r: &Row) -> rusqlite::Result<User> {
    Ok(User {
        id: r.get(0)?,
        login: r.get(1)?,
        is_org: r.get::<_, String>(2)? == "org",
        login_name: r.get(3)?,
        full_name: r.get(4)?,
        email: r.get(5)?,
        description: r.get(6)?,
        website: r.get(7)?,
        location: r.get(8)?,
        password_hash: r.get(9)?,
        must_change_password: r.get(10)?,
        is_admin: r.get(11)?,
        visibility: r.get(12)?,
        created: r.get(13)?,
    })
}

/// Fields for a new user or organization.
#[derive(Default)]
pub struct NewAccount {
    pub login: String,
    pub is_org: bool,
    pub login_name: String,
    pub full_name: String,
    pub email: String,
    pub description: String,
    pub website: String,
    pub location: String,
    pub password_hash: String,
    pub must_change_password: bool,
    pub is_admin: bool,
    pub visibility: String,
}

/// Why a store operation failed.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("exists")]
    Exists,
    #[error("not found")]
    NotFound,
    #[error("{0}")]
    Db(#[from] rusqlite::Error),
}

fn is_unique(e: &rusqlite::Error) -> bool {
    matches!(e, rusqlite::Error::SqliteFailure(f, _)
        if f.code == rusqlite::ErrorCode::ConstraintViolation)
}

/// Insert a user or organization. `Exists` when the lower-cased login is taken.
pub fn create_account(conn: &Connection, a: &NewAccount, now: i64) -> Result<User, StoreError> {
    let r = conn.execute(
        "INSERT INTO users (login, lower_login, kind, login_name, full_name, email, description, \
         website, location, password_hash, must_change_password, is_admin, visibility, created_unix) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
        params![
            a.login,
            a.login.to_lowercase(),
            if a.is_org { "org" } else { "user" },
            a.login_name,
            a.full_name,
            a.email,
            a.description,
            a.website,
            a.location,
            a.password_hash,
            a.must_change_password,
            a.is_admin,
            a.visibility,
            now
        ],
    );
    match r {
        Ok(_) => find_by_id(conn, conn.last_insert_rowid())?.ok_or(StoreError::NotFound),
        Err(e) if is_unique(&e) => Err(StoreError::Exists),
        Err(e) => Err(e.into()),
    }
}

/// Look up by login, case-insensitively.
pub fn find_by_login(conn: &Connection, login: &str) -> rusqlite::Result<Option<User>> {
    conn.query_row(
        &format!("SELECT {USER_COLS} FROM users WHERE lower_login = ?1"),
        [login.to_lowercase()],
        user_row,
    )
    .optional()
}

/// Look up by id.
pub fn find_by_id(conn: &Connection, id: i64) -> rusqlite::Result<Option<User>> {
    conn.query_row(
        &format!("SELECT {USER_COLS} FROM users WHERE id = ?1"),
        [id],
        user_row,
    )
    .optional()
}

/// Page of users (not organizations) and the total, ordered by id.
pub fn list_users(conn: &Connection, page: i64, limit: i64) -> rusqlite::Result<(Vec<User>, i64)> {
    let total = conn.query_row("SELECT COUNT(*) FROM users WHERE kind = 'user'", [], |r| {
        r.get(0)
    })?;
    let mut st = conn.prepare(&format!(
        "SELECT {USER_COLS} FROM users WHERE kind = 'user' ORDER BY id LIMIT ?1 OFFSET ?2"
    ))?;
    let rows = st.query_map(params![limit, (page - 1) * limit], user_row)?;
    Ok((rows.collect::<Result<_, _>>()?, total))
}

/// The login of the one user whose email is `email` (case-insensitive), as Gitea resolves a commit
/// author to an account. `None` for an empty address, no match, or an address shared by several
/// accounts (ambiguous: attribute to nobody).
pub fn login_by_email(conn: &Connection, email: &str) -> rusqlite::Result<Option<String>> {
    if email.is_empty() {
        return Ok(None);
    }
    let mut st = conn.prepare("SELECT login FROM users WHERE lower(email) = lower(?1) LIMIT 2")?;
    let found = st
        .query_map([email], |r| r.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(match found.as_slice() {
        [one] => Some(one.clone()),
        _ => None,
    })
}

/// Partial update of a user; `None` leaves a field alone.
#[derive(Default)]
pub struct UserPatch {
    pub login_name: Option<String>,
    pub full_name: Option<String>,
    pub email: Option<String>,
    pub password_hash: Option<String>,
    pub must_change_password: Option<bool>,
    pub is_admin: Option<bool>,
    pub visibility: Option<String>,
    pub description: Option<String>,
    pub website: Option<String>,
    pub location: Option<String>,
}

/// Apply `p` to user `id`. Only the supplied columns are written, in one
/// statement, so two concurrent patches of different fields cannot undo each
/// other (a stale read-modify-write could restore a revoked admin flag or an
/// old password hash).
pub fn update_user(conn: &Connection, id: i64, p: &UserPatch) -> Result<User, StoreError> {
    use rusqlite::types::Value;
    let text = |v: &Option<String>| v.clone().map(Value::Text);
    let flag = |v: Option<bool>| v.map(|b| Value::Integer(i64::from(b)));
    let cols: Vec<(&str, Value)> = [
        ("login_name", text(&p.login_name)),
        ("full_name", text(&p.full_name)),
        ("email", text(&p.email)),
        ("password_hash", text(&p.password_hash)),
        ("must_change_password", flag(p.must_change_password)),
        ("is_admin", flag(p.is_admin)),
        ("visibility", text(&p.visibility)),
        ("description", text(&p.description)),
        ("website", text(&p.website)),
        ("location", text(&p.location)),
    ]
    .into_iter()
    .filter_map(|(c, v)| v.map(|v| (c, v)))
    .collect();
    if !cols.is_empty() {
        let set = cols
            .iter()
            .map(|(c, _)| format!("{c} = ?"))
            .collect::<Vec<_>>()
            .join(", ");
        let mut args: Vec<Value> = cols.into_iter().map(|(_, v)| v).collect();
        args.push(Value::Integer(id));
        // Column names above are literals; only values are bound.
        if conn.execute(
            &format!("UPDATE users SET {set} WHERE id = ?"),
            rusqlite::params_from_iter(args),
        )? == 0
        {
            return Err(StoreError::NotFound);
        }
    }
    find_by_id(conn, id)?.ok_or(StoreError::NotFound)
}

/// Create an organization and make `owner` its (only kind of) member.
/// shortcut: F1 has owners only, no teams or member roles; extend `org_members`
/// with a role column if teams ever arrive.
pub fn create_org(
    conn: &mut Connection,
    a: &NewAccount,
    owner: i64,
    now: i64,
) -> Result<User, StoreError> {
    let tx = conn.transaction()?;
    let org = create_account(&tx, a, now)?;
    tx.execute(
        "INSERT INTO org_members (org_id, user_id) VALUES (?1, ?2)",
        [org.id, owner],
    )?;
    tx.commit()?;
    Ok(org)
}

/// Is `user` an owner of `org`?
pub fn is_org_owner(conn: &Connection, org: i64, user: i64) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT 1 FROM org_members WHERE org_id = ?1 AND user_id = ?2",
        [org, user],
        |_| Ok(()),
    )
    .optional()
    .map(|o| o.is_some())
}

/// A stored access token (never the secret itself).
#[derive(Clone, Debug)]
pub struct Token {
    pub id: i64,
    pub name: String,
    pub last_eight: String,
    pub scopes: Vec<String>,
    pub expires: Option<i64>,
}

fn token_row(r: &Row) -> rusqlite::Result<Token> {
    let scopes: String = r.get(3)?;
    Ok(Token {
        id: r.get(0)?,
        name: r.get(1)?,
        last_eight: r.get(2)?,
        scopes: scopes
            .split(',')
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect(),
        expires: r.get(4)?,
    })
}

/// Mint a token for `user`. Returns the stored row and the one-time secret.
/// `Exists` when the user already has a token of that name.
pub fn create_token(
    conn: &Connection,
    user: i64,
    name: &str,
    scopes: &[String],
    now: i64,
) -> Result<(Token, String), StoreError> {
    let secret = generate_token();
    let r = conn.execute(
        "INSERT INTO tokens (user_id, name, hash, last_eight, scopes, created_unix) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            user,
            name,
            hash_token(&secret),
            &secret[secret.len() - 8..],
            scopes.join(","),
            now
        ],
    );
    match r {
        Ok(_) => {
            let t = conn.query_row(
                "SELECT id, name, last_eight, scopes, expires_unix FROM tokens WHERE id = ?1",
                [conn.last_insert_rowid()],
                token_row,
            )?;
            Ok((t, secret))
        }
        Err(e) if is_unique(&e) => Err(StoreError::Exists),
        Err(e) => Err(e.into()),
    }
}

/// Page of `user`'s tokens and the total, newest first (Gitea's order; ties by id).
pub fn list_tokens(
    conn: &Connection,
    user: i64,
    page: i64,
    limit: i64,
) -> rusqlite::Result<(Vec<Token>, i64)> {
    let total = conn.query_row(
        "SELECT COUNT(*) FROM tokens WHERE user_id = ?1",
        [user],
        |r| r.get(0),
    )?;
    let mut st = conn.prepare(
        "SELECT id, name, last_eight, scopes, expires_unix FROM tokens WHERE user_id = ?1 \
         ORDER BY created_unix DESC, id ASC LIMIT ?2 OFFSET ?3",
    )?;
    let rows = st.query_map(params![user, limit, (page - 1) * limit], token_row)?;
    Ok((rows.collect::<Result<_, _>>()?, total))
}

/// Delete `user`'s token by numeric id or by name. Returns whether one existed.
pub fn delete_token(conn: &Connection, user: i64, id_or_name: &str) -> rusqlite::Result<bool> {
    let n = match id_or_name.parse::<i64>() {
        Ok(id) => conn.execute(
            "DELETE FROM tokens WHERE user_id = ?1 AND id = ?2",
            params![user, id],
        )?,
        Err(_) => 0,
    };
    if n > 0 {
        return Ok(true);
    }
    Ok(conn.execute(
        "DELETE FROM tokens WHERE user_id = ?1 AND name = ?2",
        params![user, id_or_name],
    )? > 0)
}

/// Resolve a presented token secret to its owner, token row and expiry state.
/// An expired token resolves to `None`, same as an unknown one.
pub fn resolve_token(
    conn: &Connection,
    secret: &str,
    now: i64,
) -> rusqlite::Result<Option<(User, Token)>> {
    let hash = hash_token(secret);
    let row: Option<(i64, Token)> = conn
        .query_row(
            "SELECT user_id, id, name, last_eight, scopes, expires_unix FROM tokens WHERE hash = ?1",
            [&hash],
            |r| {
                let uid: i64 = r.get(0)?;
                let scopes: String = r.get(4)?;
                Ok((
                    uid,
                    Token {
                        id: r.get(1)?,
                        name: r.get(2)?,
                        last_eight: r.get(3)?,
                        scopes: scopes.split(',').filter(|s| !s.is_empty()).map(String::from).collect(),
                        expires: r.get(5)?,
                    },
                ))
            },
        )
        .optional()?;
    let Some((uid, tok)) = row else {
        return Ok(None);
    };
    if tok.expires.is_some_and(|e| e <= now) {
        return Ok(None);
    }
    Ok(find_by_id(conn, uid)?
        .filter(|u| !u.is_org)
        .map(|u| (u, tok)))
}

/// Normalize-then-store convenience used by the CLI and the API.
pub fn mint(
    conn: &Connection,
    user: i64,
    name: &str,
    requested: &[String],
    now: i64,
) -> Result<(Token, String), MintError> {
    let scopes = scope::normalize(requested).map_err(MintError::BadScope)?;
    create_token(conn, user, name, &scopes, now).map_err(MintError::Store)
}

/// Why `mint` failed.
#[derive(Debug)]
pub enum MintError {
    BadScope(String),
    Store(StoreError),
}
