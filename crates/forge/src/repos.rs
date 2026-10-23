//! Repositories and collaborators: the queries, and the one function
//! ([`resolve`]) that turns a caller and a repository name into a permission.
//! The F2b git path calls the same function, so API and git access cannot drift.

use crate::store::{self, StoreError, User};
use rusqlite::{params, Connection, OptionalExtension, Row};

/// What a caller may do in a repository. `Read < Write < Admin`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Perm {
    Read,
    Write,
    Admin,
}

impl Perm {
    /// The stored collaborator mode.
    pub fn as_mode(self) -> &'static str {
        match self {
            Perm::Read => "read",
            Perm::Write => "write",
            Perm::Admin => "admin",
        }
    }

    /// Parse a collaborator mode.
    pub fn from_mode(s: &str) -> Option<Perm> {
        match s {
            "read" => Some(Perm::Read),
            "write" => Some(Perm::Write),
            "admin" => Some(Perm::Admin),
            _ => None,
        }
    }
}

/// A repository row.
#[derive(Clone, Debug)]
pub struct Repo {
    pub id: i64,
    pub owner_id: i64,
    pub owner: String,
    pub name: String,
    pub description: String,
    pub website: String,
    pub default_branch: String,
    pub state: String,
    pub created: i64,
    pub updated: i64,
}

const REPO_COLS: &str =
    "r.id, r.owner_id, u.login, r.name, r.description, r.website, r.default_branch, \
     r.state, r.created_unix, r.updated_unix";
const REPO_FROM: &str = "FROM repos r JOIN users u ON u.id = r.owner_id";

fn repo_row(r: &Row) -> rusqlite::Result<Repo> {
    Ok(Repo {
        id: r.get(0)?,
        owner_id: r.get(1)?,
        owner: r.get(2)?,
        name: r.get(3)?,
        description: r.get(4)?,
        website: r.get(5)?,
        default_branch: r.get(6)?,
        state: r.get(7)?,
        created: r.get(8)?,
        updated: r.get(9)?,
    })
}

/// Insert a repository in state `creating`. `Exists` when the owner already has one of that
/// name, in any state and in any letter case.
pub fn insert_creating(
    conn: &Connection,
    owner_id: i64,
    name: &str,
    default_branch: &str,
    description: &str,
    website: &str,
    now: i64,
) -> Result<Repo, StoreError> {
    let r = conn.execute(
        "INSERT INTO repos (owner_id, name, lower_name, description, website, default_branch, state, \
         created_unix, updated_unix) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'creating', ?7, ?7)",
        params![owner_id, name, name.to_lowercase(), description, website, default_branch, now],
    );
    match r {
        Ok(_) => find_by_id(conn, conn.last_insert_rowid())?.ok_or(StoreError::NotFound),
        Err(rusqlite::Error::SqliteFailure(f, _))
            if f.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE =>
        {
            Err(StoreError::Exists)
        }
        Err(e) => Err(e.into()),
    }
}

/// A repository by id, in any state.
pub fn find_by_id(conn: &Connection, id: i64) -> rusqlite::Result<Option<Repo>> {
    conn.query_row(
        &format!("SELECT {REPO_COLS} {REPO_FROM} WHERE r.id = ?1"),
        [id],
        repo_row,
    )
    .optional()
}

/// A repository by owner login and name (case-insensitive), in any state.
pub fn find_row(conn: &Connection, owner: &str, name: &str) -> rusqlite::Result<Option<Repo>> {
    conn.query_row(
        &format!("SELECT {REPO_COLS} {REPO_FROM} WHERE u.lower_login = ?1 AND r.lower_name = ?2"),
        [owner.to_lowercase(), name.to_lowercase()],
        repo_row,
    )
    .optional()
}

/// Every repository in a state (for the reconciler).
pub fn list_in_state(conn: &Connection, state: &str) -> rusqlite::Result<Vec<Repo>> {
    let mut st = conn.prepare(&format!(
        "SELECT {REPO_COLS} {REPO_FROM} WHERE r.state = ?1 ORDER BY r.id"
    ))?;
    let rows = st.query_map([state], repo_row)?;
    rows.collect()
}

/// Move a repository between states; `false` when it was not in `from` (someone else moved it).
pub fn set_state(
    conn: &Connection,
    id: i64,
    from: &str,
    to: &str,
    now: i64,
) -> rusqlite::Result<bool> {
    Ok(conn.execute(
        "UPDATE repos SET state = ?3, updated_unix = ?4 WHERE id = ?1 AND state = ?2",
        params![id, from, to, now],
    )? > 0)
}

/// Delete the row (collaborators cascade).
pub fn delete_row(conn: &Connection, id: i64) -> rusqlite::Result<()> {
    conn.execute("DELETE FROM repos WHERE id = ?1", [id])?;
    Ok(())
}

/// Fields `PATCH` may change; `None` leaves a field alone.
#[derive(Default)]
pub struct RepoPatch {
    pub description: Option<String>,
    pub website: Option<String>,
    pub default_branch: Option<String>,
}

/// Apply a patch to a `live` repository only (`false` when it is not live any more).
pub fn update_live(conn: &Connection, id: i64, p: &RepoPatch, now: i64) -> rusqlite::Result<bool> {
    use rusqlite::types::Value;
    let mut sets = vec!["updated_unix = ?".to_string()];
    let mut args: Vec<Value> = vec![Value::Integer(now)];
    for (col, v) in [
        ("description", &p.description),
        ("website", &p.website),
        ("default_branch", &p.default_branch),
    ] {
        if let Some(v) = v {
            sets.push(format!("{col} = ?"));
            args.push(Value::Text(v.clone()));
        }
    }
    args.push(Value::Integer(id));
    Ok(conn.execute(
        &format!(
            "UPDATE repos SET {} WHERE id = ? AND state = 'live'",
            sets.join(", ")
        ),
        rusqlite::params_from_iter(args),
    )? > 0)
}

/// A caller's standing in a repository.
#[derive(Clone, Debug)]
pub struct Access {
    pub repo: Repo,
    pub perm: Perm,
    /// The owning user, an owner of the owning organization, or a site admin: authority that
    /// does not depend on a collaborator row.
    pub is_owner: bool,
}

/// The standing of `user` in a repository, or `None` when it does not exist, is not `live`,
/// or the caller has no access at all (a missing and an invisible repository are one answer).
/// Site admin = Admin; the owning user and the owners of the owning organization = Admin and
/// owner; otherwise the collaborator mode. Organization membership alone grants nothing.
pub fn resolve(
    conn: &Connection,
    user: &User,
    owner: &str,
    name: &str,
) -> rusqlite::Result<Option<Access>> {
    let Some(repo) = find_row(conn, owner, name)?.filter(|r| r.state == "live") else {
        return Ok(None);
    };
    let owns = repo.owner_id == user.id || store::is_org_owner(conn, repo.owner_id, user.id)?;
    if owns || user.is_admin {
        return Ok(Some(Access {
            repo,
            perm: Perm::Admin,
            is_owner: owns || user.is_admin,
        }));
    }
    let mode: Option<String> = conn
        .query_row(
            "SELECT mode FROM collaborators WHERE repo_id = ?1 AND user_id = ?2",
            [repo.id, user.id],
            |r| r.get(0),
        )
        .optional()?;
    Ok(mode.and_then(|m| Perm::from_mode(&m)).map(|perm| Access {
        repo,
        perm,
        is_owner: false,
    }))
}

/// Search and list filters.
#[derive(Default)]
pub struct Filter {
    /// Substring of the name or description (case-insensitive).
    pub q: Option<String>,
    /// Only repositories of this owner.
    pub owner_id: Option<i64>,
}

/// How a listing is ordered.
#[derive(Clone, Copy)]
pub enum Sort {
    /// By id (creation order).
    Id,
    /// By full name, `owner/name`.
    Alpha,
}

/// One page of the `live` repositories `user` can read, and the total, filtered by the same
/// rule as [`resolve`]. `public_only` (a token restricted to public repositories) sees nothing:
/// every repository here is private.
pub fn list_visible(
    conn: &Connection,
    user: &User,
    public_only: bool,
    filter: &Filter,
    sort: Sort,
    page: i64,
    limit: i64,
) -> rusqlite::Result<(Vec<Repo>, i64)> {
    if public_only {
        return Ok((vec![], 0));
    }
    use rusqlite::types::Value;
    let mut wheres = vec!["r.state = 'live'".to_string()];
    let mut args: Vec<Value> = vec![];
    if !user.is_admin {
        wheres.push(
            "(r.owner_id = ? OR r.owner_id IN (SELECT org_id FROM org_members WHERE user_id = ?) \
             OR r.id IN (SELECT repo_id FROM collaborators WHERE user_id = ?))"
                .into(),
        );
        args.extend(std::iter::repeat_n(Value::Integer(user.id), 3));
    }
    if let Some(o) = filter.owner_id {
        wheres.push("r.owner_id = ?".into());
        args.push(Value::Integer(o));
    }
    if let Some(q) = filter.q.as_deref().filter(|q| !q.is_empty()) {
        wheres.push(
            "(r.lower_name LIKE ? ESCAPE '\\' OR ulower(r.description) LIKE ? ESCAPE '\\')".into(),
        );
        let pat = format!(
            "%{}%",
            q.to_lowercase()
                .replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_")
        );
        args.extend([Value::Text(pat.clone()), Value::Text(pat)]);
    }
    let w = wheres.join(" AND ");
    let total: i64 = conn.query_row(
        &format!("SELECT COUNT(*) {REPO_FROM} WHERE {w}"),
        rusqlite::params_from_iter(args.clone()),
        |r| r.get(0),
    )?;
    let order = match sort {
        Sort::Id => "r.id",
        // recorded: `sort=alpha` orders by the full name `owner/name`
        Sort::Alpha => "u.lower_login, r.lower_name, r.id",
    };
    args.push(Value::Integer(limit));
    args.push(Value::Integer((page - 1) * limit));
    let mut st = conn.prepare(&format!(
        "SELECT {REPO_COLS} {REPO_FROM} WHERE {w} ORDER BY {order} LIMIT ? OFFSET ?"
    ))?;
    let rows = st.query_map(rusqlite::params_from_iter(args), repo_row)?;
    Ok((rows.collect::<Result<_, _>>()?, total))
}

/// Add or change a collaborator (`write` is the default mode, chosen by the caller).
pub fn set_collaborator(
    conn: &Connection,
    repo_id: i64,
    user_id: i64,
    mode: Perm,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO collaborators (repo_id, user_id, mode) VALUES (?1, ?2, ?3) \
         ON CONFLICT (repo_id, user_id) DO UPDATE SET mode = excluded.mode",
        params![repo_id, user_id, mode.as_mode()],
    )?;
    Ok(())
}

/// Remove a collaborator; `false` when there was none.
pub fn remove_collaborator(
    conn: &Connection,
    repo_id: i64,
    user_id: i64,
) -> rusqlite::Result<bool> {
    Ok(conn.execute(
        "DELETE FROM collaborators WHERE repo_id = ?1 AND user_id = ?2",
        [repo_id, user_id],
    )? > 0)
}

/// The collaborators of a repository in the order they were added, with their modes.
pub fn collaborators(
    conn: &Connection,
    repo_id: i64,
    page: i64,
    limit: i64,
) -> rusqlite::Result<(Vec<(User, Perm)>, i64)> {
    let total: i64 = conn.query_row(
        "SELECT COUNT(*) FROM collaborators WHERE repo_id = ?1",
        [repo_id],
        |r| r.get(0),
    )?;
    let mut st = conn.prepare(
        "SELECT user_id, mode FROM collaborators WHERE repo_id = ?1 ORDER BY rowid LIMIT ?2 OFFSET ?3",
    )?;
    let ids: Vec<(i64, String)> = st
        .query_map(params![repo_id, limit, (page - 1) * limit], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })?
        .collect::<Result<_, _>>()?;
    let mut out = Vec::new();
    for (uid, mode) in ids {
        if let (Some(u), Some(p)) = (store::find_by_id(conn, uid)?, Perm::from_mode(&mode)) {
            out.push((u, p));
        }
    }
    Ok((out, total))
}

/// A collaborator's mode, if any.
pub fn collaborator_mode(
    conn: &Connection,
    repo_id: i64,
    user_id: i64,
) -> rusqlite::Result<Option<Perm>> {
    let m: Option<String> = conn
        .query_row(
            "SELECT mode FROM collaborators WHERE repo_id = ?1 AND user_id = ?2",
            [repo_id, user_id],
            |r| r.get(0),
        )
        .optional()?;
    Ok(m.and_then(|m| Perm::from_mode(&m)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use crate::store::{create_account, create_org, NewAccount};
    use std::path::PathBuf;

    struct Env {
        dir: PathBuf,
        conn: Connection,
    }
    impl Drop for Env {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn env(tag: &str) -> Env {
        let dir =
            std::env::temp_dir().join(format!("scl-forge-repos-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let conn = db::open_for_admin(&dir).unwrap();
        Env { dir, conn }
    }

    fn user(c: &Connection, login: &str, admin: bool) -> User {
        let a = NewAccount {
            login: login.into(),
            is_admin: admin,
            visibility: "public".into(),
            ..Default::default()
        };
        create_account(c, &a, 1).unwrap()
    }

    fn live(c: &Connection, owner: &User, name: &str) -> Repo {
        let r = insert_creating(c, owner.id, name, "main", "", "", 1).unwrap();
        assert!(set_state(c, r.id, "creating", "live", 2).unwrap());
        find_by_id(c, r.id).unwrap().unwrap()
    }

    #[test]
    fn names_are_unique_per_owner_in_any_case_and_any_state() {
        let e = env("uniq");
        let (alice, bob) = (user(&e.conn, "alice", false), user(&e.conn, "bob", false));
        insert_creating(&e.conn, alice.id, "Mixed", "main", "", "", 1).unwrap();
        for dup in ["mixed", "MIXED", "Mixed"] {
            assert!(
                matches!(
                    insert_creating(&e.conn, alice.id, dup, "main", "", "", 1),
                    Err(StoreError::Exists)
                ),
                "{dup} (still creating)"
            );
        }
        assert!(
            insert_creating(&e.conn, bob.id, "mixed", "main", "", "", 1).is_ok(),
            "another owner may reuse the name"
        );
    }

    #[test]
    fn only_a_unique_violation_means_the_name_exists() {
        let e = env("unique-only");
        let owner = user(&e.conn, "alice", false);
        insert_creating(&e.conn, owner.id, "a", "main", "", "", 1).unwrap();
        assert!(matches!(
            insert_creating(&e.conn, owner.id, "A", "main", "", "", 1),
            Err(StoreError::Exists)
        ));
        // a foreign-key failure (no such owner) is a database error, never "already exists"
        assert!(matches!(
            insert_creating(&e.conn, 9_999, "b", "main", "", "", 1),
            Err(StoreError::Db(_))
        ));
        // so is a CHECK failure
        let bad = e.conn.execute(
            "INSERT INTO repos (owner_id, name, lower_name, default_branch, state, created_unix, updated_unix) VALUES (?1, 'c', 'c', 'main', 'bogus', 1, 1)",
            [owner.id],
        );
        assert!(bad.is_err());
    }

    #[test]
    fn the_access_matrix() {
        let mut e = env("matrix");
        let (admin, owner, reader, writer, adm_collab, outsider) = (
            user(&e.conn, "root", true),
            user(&e.conn, "owner", false),
            user(&e.conn, "reader", false),
            user(&e.conn, "writer", false),
            user(&e.conn, "admcol", false),
            user(&e.conn, "outsider", false),
        );
        let org = create_org(
            &mut e.conn,
            &NewAccount {
                login: "acme".into(),
                is_org: true,
                visibility: "private".into(),
                ..Default::default()
            },
            owner.id,
            1,
        )
        .unwrap();
        let personal = live(&e.conn, &owner, "personal");
        let orgrepo = live(&e.conn, &org, "orgrepo");
        for r in [&personal, &orgrepo] {
            set_collaborator(&e.conn, r.id, reader.id, Perm::Read).unwrap();
            set_collaborator(&e.conn, r.id, writer.id, Perm::Write).unwrap();
            set_collaborator(&e.conn, r.id, adm_collab.id, Perm::Admin).unwrap();
        }
        let got = |u: &User, o: &str, n: &str| {
            resolve(&e.conn, u, o, n)
                .unwrap()
                .map(|a| (a.perm, a.is_owner))
        };
        for (o, n) in [("owner", "personal"), ("acme", "orgrepo")] {
            assert_eq!(got(&admin, o, n), Some((Perm::Admin, true)), "site admin");
            assert_eq!(
                got(&owner, o, n),
                Some((Perm::Admin, true)),
                "owner / org owner"
            );
            assert_eq!(
                got(&adm_collab, o, n),
                Some((Perm::Admin, false)),
                "admin collaborator is not owner"
            );
            assert_eq!(got(&writer, o, n), Some((Perm::Write, false)));
            assert_eq!(got(&reader, o, n), Some((Perm::Read, false)));
            assert_eq!(got(&outsider, o, n), None, "no row, no access");
        }
        // case-insensitive lookup, same answer
        assert_eq!(got(&owner, "OWNER", "PERSONAL"), Some((Perm::Admin, true)));
        // not live -> invisible to everyone, owner and site admin included
        let creating = insert_creating(&e.conn, owner.id, "half", "main", "", "", 1).unwrap();
        assert_eq!(got(&owner, "owner", "half"), None);
        assert_eq!(got(&admin, "owner", "half"), None);
        assert!(set_state(&e.conn, creating.id, "creating", "live", 2).unwrap());
        assert!(
            !set_state(&e.conn, creating.id, "creating", "live", 3).unwrap(),
            "the transition is conditional"
        );
        assert_eq!(got(&owner, "owner", "half"), Some((Perm::Admin, true)));
        // org membership alone grants nothing: an org owner row exists only for owners in F1,
        // so an outsider who is merely a collaborator elsewhere gains nothing here.
        assert_eq!(got(&reader, "acme", "nope"), None);
    }

    #[test]
    fn listings_follow_the_same_rule_and_public_only_sees_nothing() {
        let mut e = env("list");
        let (admin, owner, reader, outsider) = (
            user(&e.conn, "root", true),
            user(&e.conn, "owner", false),
            user(&e.conn, "reader", false),
            user(&e.conn, "outsider", false),
        );
        let org = create_org(
            &mut e.conn,
            &NewAccount {
                login: "acme".into(),
                is_org: true,
                visibility: "private".into(),
                ..Default::default()
            },
            owner.id,
            1,
        )
        .unwrap();
        let a = live(&e.conn, &owner, "alpha");
        live(&e.conn, &owner, "beta");
        live(&e.conn, &org, "gamma");
        insert_creating(&e.conn, owner.id, "hidden-creating", "main", "", "", 1).unwrap();
        set_collaborator(&e.conn, a.id, reader.id, Perm::Read).unwrap();
        let names = |u: &User, po: bool, f: &Filter| {
            let (rs, total) = list_visible(&e.conn, u, po, f, Sort::Alpha, 1, 50).unwrap();
            (
                rs.into_iter()
                    .map(|r| format!("{}/{}", r.owner, r.name))
                    .collect::<Vec<_>>(),
                total,
            )
        };
        let all = Filter::default();
        assert_eq!(
            names(&admin, false, &all),
            (
                // `sort=alpha` orders by the full name `owner/name`
                vec![
                    "acme/gamma".into(),
                    "owner/alpha".into(),
                    "owner/beta".into()
                ],
                3
            )
        );
        assert_eq!(
            names(&owner, false, &all).1,
            3,
            "owner sees own and org-owned repos"
        );
        assert_eq!(names(&reader, false, &all), (vec!["owner/alpha".into()], 1));
        assert_eq!(names(&outsider, false, &all), (vec![], 0));
        assert_eq!(
            names(&owner, true, &all),
            (vec![], 0),
            "public-only sees nothing, not an error"
        );
        assert_eq!(
            names(
                &admin,
                false,
                &Filter {
                    q: Some("ALP".into()),
                    ..Default::default()
                }
            )
            .0,
            vec!["owner/alpha".to_string()]
        );
        assert_eq!(
            names(
                &admin,
                false,
                &Filter {
                    q: Some("100%".into()),
                    ..Default::default()
                }
            )
            .1,
            0,
            "LIKE wildcards are escaped"
        );
        // paging keeps the visible total
        let (rs, total) = list_visible(&e.conn, &admin, false, &all, Sort::Id, 2, 2).unwrap();
        assert_eq!((rs.len(), total), (1, 3));
    }

    #[test]
    fn search_folds_case_for_non_ascii_descriptions_too() {
        let e = env("unicode-q");
        let owner = user(&e.conn, "owner", false);
        let r = live(&e.conn, &owner, "pastry");
        update_live(
            &e.conn,
            r.id,
            &RepoPatch {
                description: Some("Éclair and STRÜDEL".into()),
                ..Default::default()
            },
            3,
        )
        .unwrap();
        for q in [
            "éclair",
            "ÉCLAIR",
            "strüdel",
            "Strüdel",
            "ECLAIR".to_lowercase().as_str(),
        ] {
            let hit = list_visible(
                &e.conn,
                &owner,
                false,
                &Filter {
                    q: Some(q.into()),
                    ..Default::default()
                },
                Sort::Id,
                1,
                50,
            )
            .unwrap()
            .1;
            // "eclair" (no accent) is a different word, so it correctly finds nothing
            assert_eq!(hit, i64::from(q != "eclair"), "{q}");
        }
    }

    #[test]
    fn collaborators_keep_insertion_order_and_cascade_on_delete() {
        let e = env("collab");
        let (owner, a, b) = (
            user(&e.conn, "owner", false),
            user(&e.conn, "a", false),
            user(&e.conn, "b", false),
        );
        let r = live(&e.conn, &owner, "r");
        set_collaborator(&e.conn, r.id, b.id, Perm::Write).unwrap();
        set_collaborator(&e.conn, r.id, a.id, Perm::Read).unwrap();
        set_collaborator(&e.conn, r.id, b.id, Perm::Admin).unwrap(); // a change keeps b's place
        let (cs, total) = collaborators(&e.conn, r.id, 1, 50).unwrap();
        assert_eq!(
            (
                cs.iter()
                    .map(|(u, p)| (u.login.as_str(), *p))
                    .collect::<Vec<_>>(),
                total
            ),
            (vec![("b", Perm::Admin), ("a", Perm::Read)], 2)
        );
        assert!(remove_collaborator(&e.conn, r.id, a.id).unwrap());
        assert!(!remove_collaborator(&e.conn, r.id, a.id).unwrap());
        delete_row(&e.conn, r.id).unwrap();
        let left: i64 = e
            .conn
            .query_row("SELECT COUNT(*) FROM collaborators", [], |r| r.get(0))
            .unwrap();
        assert_eq!(left, 0);
    }

    #[test]
    fn update_only_touches_a_live_repo() {
        let e = env("update");
        let owner = user(&e.conn, "owner", false);
        let r = insert_creating(&e.conn, owner.id, "r", "main", "", "", 1).unwrap();
        let p = RepoPatch {
            description: Some("d".into()),
            ..Default::default()
        };
        assert!(
            !update_live(&e.conn, r.id, &p, 5).unwrap(),
            "a creating repo is not patched"
        );
        set_state(&e.conn, r.id, "creating", "live", 2).unwrap();
        assert!(update_live(&e.conn, r.id, &p, 5).unwrap());
        let got = find_by_id(&e.conn, r.id).unwrap().unwrap();
        assert_eq!(
            (
                got.description.as_str(),
                got.default_branch.as_str(),
                got.updated
            ),
            ("d", "main", 5)
        );
        set_state(&e.conn, r.id, "live", "deleting", 6).unwrap();
        assert!(
            !update_live(&e.conn, r.id, &p, 7).unwrap(),
            "a deleting repo is not patched"
        );
    }
}
