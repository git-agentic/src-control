//! SQLite metadata: connection settings and numbered migrations.
//!
//! `serve` migrates at startup; `admin` migrates only a database that does not
//! exist yet (or is at schema version 0), so the documented `admin user create`
//! then `serve` sequence works on an empty data directory. On an existing
//! database `admin` refuses a version mismatch, and `serve` refuses a schema
//! newer than its own.

use rusqlite::Connection;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// Schema version this binary reads and writes.
pub const SCHEMA_VERSION: i64 = MIGRATIONS.len() as i64;

const MIGRATIONS: &[&str] = &[
    // 1: users and organizations (one table), org owners, access tokens.
    "CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        login TEXT NOT NULL,
        lower_login TEXT NOT NULL UNIQUE,
        kind TEXT NOT NULL CHECK (kind IN ('user', 'org')),
        login_name TEXT NOT NULL DEFAULT '',
        full_name TEXT NOT NULL DEFAULT '',
        email TEXT NOT NULL DEFAULT '',
        description TEXT NOT NULL DEFAULT '',
        website TEXT NOT NULL DEFAULT '',
        location TEXT NOT NULL DEFAULT '',
        password_hash TEXT NOT NULL DEFAULT '',
        must_change_password INTEGER NOT NULL DEFAULT 0,
        is_admin INTEGER NOT NULL DEFAULT 0,
        visibility TEXT NOT NULL DEFAULT 'public'
            CHECK (visibility IN ('public', 'limited', 'private')),
        created_unix INTEGER NOT NULL
    );
    CREATE TABLE org_members (
        org_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        PRIMARY KEY (org_id, user_id)
    );
    CREATE TABLE tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        hash TEXT NOT NULL UNIQUE,
        last_eight TEXT NOT NULL,
        scopes TEXT NOT NULL,
        created_unix INTEGER NOT NULL,
        expires_unix INTEGER,
        UNIQUE (user_id, name)
    );",
    // 2: repositories (named by immutable id on disk) and collaborators. `private` is not
    // stored: every repository is private.
    "CREATE TABLE repos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        owner_id INTEGER NOT NULL REFERENCES users(id),
        name TEXT NOT NULL,
        lower_name TEXT NOT NULL,
        description TEXT NOT NULL DEFAULT '',
        website TEXT NOT NULL DEFAULT '',
        default_branch TEXT NOT NULL,
        state TEXT NOT NULL CHECK (state IN ('creating', 'live', 'deleting')),
        created_unix INTEGER NOT NULL,
        updated_unix INTEGER NOT NULL,
        UNIQUE (owner_id, lower_name)
    );
    CREATE TABLE collaborators (
        repo_id INTEGER NOT NULL REFERENCES repos(id) ON DELETE CASCADE,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        mode TEXT NOT NULL CHECK (mode IN ('read', 'write', 'admin')),
        PRIMARY KEY (repo_id, user_id)
    );",
    // 3: branch protection rules (exact branch names; `lower_branch` is the Unicode-lowercased
    // name the case-insensitive uniqueness and matching use; `status_check_contexts` is a JSON
    // array, NULL when the request gave none) and commit statuses (latest per context is the
    // highest id).
    "CREATE TABLE branch_protections (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        repo_id INTEGER NOT NULL REFERENCES repos(id) ON DELETE CASCADE,
        branch TEXT NOT NULL,
        lower_branch TEXT NOT NULL,
        enable_push INTEGER NOT NULL DEFAULT 0,
        enable_status_check INTEGER NOT NULL DEFAULT 0,
        status_check_contexts TEXT,
        created_unix INTEGER NOT NULL,
        updated_unix INTEGER NOT NULL,
        UNIQUE (repo_id, lower_branch)
    );
    CREATE TABLE commit_statuses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        repo_id INTEGER NOT NULL REFERENCES repos(id) ON DELETE CASCADE,
        sha TEXT NOT NULL,
        context TEXT NOT NULL,
        state TEXT NOT NULL
            CHECK (state IN ('pending', 'success', 'error', 'failure', 'warning', 'skipped')),
        description TEXT NOT NULL DEFAULT '',
        target_url TEXT NOT NULL DEFAULT '',
        creator_id INTEGER NOT NULL REFERENCES users(id),
        created_unix INTEGER NOT NULL,
        updated_unix INTEGER NOT NULL
    );
    CREATE INDEX commit_statuses_by_sha ON commit_statuses (repo_id, sha, context, id);",
    // 4: pull requests (one number sequence per repository, one open PR per head/base pair),
    // the mergeability cache keyed by the two immutable object ids, reviews, and issue comments
    // (the number of an issue comment is the PR number). `state` merged is set by F4c.
    "CREATE TABLE pulls (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        repo_id INTEGER NOT NULL REFERENCES repos(id) ON DELETE CASCADE,
        number INTEGER NOT NULL,
        head_ref TEXT NOT NULL,
        base_ref TEXT NOT NULL,
        base_sha TEXT NOT NULL,
        head_sha TEXT NOT NULL,
        title TEXT NOT NULL,
        body TEXT NOT NULL DEFAULT '',
        state TEXT NOT NULL CHECK (state IN ('open', 'closed', 'merged')),
        creator_id INTEGER NOT NULL REFERENCES users(id),
        created_unix INTEGER NOT NULL,
        updated_unix INTEGER NOT NULL,
        closed_unix INTEGER,
        final_head_sha TEXT,
        merge_commit_sha TEXT,
        merged_unix INTEGER,
        merged_by INTEGER REFERENCES users(id),
        merge_base TEXT,
        changed_files INTEGER,
        additions INTEGER,
        deletions INTEGER,
        head_gone INTEGER NOT NULL DEFAULT 0,
        UNIQUE (repo_id, number)
    );
    CREATE UNIQUE INDEX pulls_one_open ON pulls (repo_id, head_ref, base_ref) WHERE state = 'open';
    CREATE TABLE mergeability_cache (
        repo_id INTEGER NOT NULL REFERENCES repos(id) ON DELETE CASCADE,
        base_sha TEXT NOT NULL,
        head_sha TEXT NOT NULL,
        mergeable INTEGER NOT NULL,
        merge_base TEXT NOT NULL DEFAULT '',
        changed_files INTEGER NOT NULL,
        additions INTEGER NOT NULL,
        deletions INTEGER NOT NULL,
        PRIMARY KEY (repo_id, base_sha, head_sha)
    );
    CREATE TABLE reviews (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        repo_id INTEGER NOT NULL REFERENCES repos(id) ON DELETE CASCADE,
        pull_number INTEGER NOT NULL,
        reviewer_id INTEGER NOT NULL REFERENCES users(id),
        state TEXT NOT NULL CHECK (state IN ('APPROVED', 'REQUEST_CHANGES', 'COMMENT', 'PENDING')),
        body TEXT NOT NULL,
        commit_id TEXT NOT NULL,
        official INTEGER NOT NULL,
        created_unix INTEGER NOT NULL
    );
    CREATE INDEX reviews_by_pull ON reviews (repo_id, pull_number, id);
    CREATE TABLE issue_comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        repo_id INTEGER NOT NULL REFERENCES repos(id) ON DELETE CASCADE,
        number INTEGER NOT NULL,
        author_id INTEGER NOT NULL REFERENCES users(id),
        body TEXT NOT NULL,
        created_unix INTEGER NOT NULL,
        updated_unix INTEGER NOT NULL
    );
    CREATE INDEX issue_comments_by_issue ON issue_comments (repo_id, number, id);",
    // 5: the merge journal. A row is written before the base branch moves; `refs/forge/merge/<id>/landed`
    // is written right after, and a crash is resolved from the marker or, failing that, from the merge
    // commit being part of the base's history (see `merges.rs`). `recovered` marks a row finished by
    // recovery rather than by the request that started it.
    "CREATE TABLE merge_intents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        repo_id INTEGER NOT NULL REFERENCES repos(id) ON DELETE CASCADE,
        pull_number INTEGER NOT NULL,
        base_ref TEXT NOT NULL,
        head_ref TEXT NOT NULL,
        base_oid TEXT NOT NULL,
        head_oid TEXT NOT NULL,
        merge_oid TEXT NOT NULL,
        merge_base TEXT NOT NULL DEFAULT '',
        changed_files INTEGER NOT NULL,
        additions INTEGER NOT NULL,
        deletions INTEGER NOT NULL,
        merger_id INTEGER NOT NULL REFERENCES users(id),
        merged_unix INTEGER NOT NULL,
        recovered INTEGER NOT NULL DEFAULT 0,
        state TEXT NOT NULL CHECK (state IN ('pending', 'done', 'aborted')),
        created_unix INTEGER NOT NULL
    );
    CREATE UNIQUE INDEX merge_intents_one_pending ON merge_intents (repo_id, pull_number) WHERE state = 'pending';",
];

/// Every table the current schema creates; `/healthz` probes each, so a missing or unreadable one
/// (whatever the recorded version says) reads as not ready.
pub const TABLES: &[&str] = &[
    "users",
    "org_members",
    "tokens",
    "repos",
    "collaborators",
    "branch_protections",
    "commit_statuses",
    "pulls",
    "mergeability_cache",
    "reviews",
    "issue_comments",
    "merge_intents",
];

/// Database failures a caller reports to the operator.
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("database error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Schema(String),
}

/// Path of the metadata database inside the data directory.
pub fn db_path(data_dir: &Path) -> PathBuf {
    data_dir.join("forge.db")
}

/// Open a connection with the durability and integrity settings every
/// connection needs (WAL, `synchronous=FULL`, foreign keys, a busy timeout).
pub fn connect(data_dir: &Path) -> Result<Connection, DbError> {
    let path = db_path(data_dir);
    let fresh = !path.exists();
    let conn = Connection::open(&path)?;
    if fresh {
        // Owner-only before WAL creates its siblings, which copy this mode.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "FULL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    // SQLite's built-in lower() folds ASCII only; searches need Unicode-aware case folding.
    conn.create_scalar_function(
        "ulower",
        1,
        rusqlite::functions::FunctionFlags::SQLITE_UTF8
            | rusqlite::functions::FunctionFlags::SQLITE_DETERMINISTIC,
        |ctx| Ok(ctx.get::<String>(0)?.to_lowercase()),
    )?;
    Ok(conn)
}

fn version(conn: &Connection) -> Result<i64, DbError> {
    Ok(conn.query_row("PRAGMA user_version", [], |r| r.get(0))?)
}

fn migrate(conn: &mut Connection) -> Result<(), DbError> {
    let have = version(conn)?;
    for (i, sql) in MIGRATIONS.iter().enumerate().skip(have as usize) {
        let tx = conn.transaction()?;
        tx.execute_batch(sql)?;
        tx.pragma_update(None, "user_version", i as i64 + 1)?;
        tx.commit()?;
    }
    Ok(())
}

/// Create the data directory and make it owner-only: the database holds
/// password and token hashes, so a pre-existing directory is tightened too.
fn ensure_dir(data_dir: &Path) -> Result<(), DbError> {
    std::fs::create_dir_all(data_dir)?;
    let mode = std::fs::metadata(data_dir)?.permissions().mode() & 0o777;
    if mode != 0o700 {
        eprintln!(
            "sc-forge: tightening {} from {mode:o} to 700: it holds password and token hashes",
            data_dir.display()
        );
        std::fs::set_permissions(data_dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Open the existing database read-only, for the `pre-receive` hook: never creates the file, never
/// migrates, never takes the data-directory lock, and refuses unless the schema is exactly this
/// binary's (a binary replaced in place without a restart fails closed).
pub fn open_readonly(data_dir: &Path) -> Result<Connection, DbError> {
    let conn = Connection::open_with_flags(
        db_path(data_dir),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    conn.pragma_update(None, "query_only", "ON")?;
    let have = version(&conn)?;
    if have != SCHEMA_VERSION {
        return Err(DbError::Schema(format!(
            "database schema {have} differs from this binary's {SCHEMA_VERSION}"
        )));
    }
    Ok(conn)
}

/// Open for `serve`: migrate forward, refuse a newer schema.
pub fn open_for_serve(data_dir: &Path) -> Result<(), DbError> {
    ensure_dir(data_dir)?;
    let mut conn = connect(data_dir)?;
    let have = version(&conn)?;
    if have > SCHEMA_VERSION {
        return Err(DbError::Schema(format!(
            "database schema {have} is newer than this binary's {SCHEMA_VERSION}; upgrade sc-forge"
        )));
    }
    migrate(&mut conn)
}

/// Open for `admin`: migrate only a new (version 0) database, refuse a mismatch.
pub fn open_for_admin(data_dir: &Path) -> Result<Connection, DbError> {
    ensure_dir(data_dir)?;
    let mut conn = connect(data_dir)?;
    let have = version(&conn)?;
    if have == 0 {
        migrate(&mut conn)?;
    } else if have != SCHEMA_VERSION {
        return Err(DbError::Schema(format!(
            "database schema {have} differs from this binary's {SCHEMA_VERSION}; run `sc-forge serve` once with the matching binary"
        )));
    }
    Ok(conn)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("scl-forge-db-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn admin_bootstraps_an_empty_dir_and_serve_accepts_it() {
        let d = tmp("boot");
        let conn = open_for_admin(&d).unwrap();
        assert_eq!(version(&conn).unwrap(), SCHEMA_VERSION);
        let mode = std::fs::metadata(&d).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "data dir holds password hashes");
        let dbmode = std::fs::metadata(db_path(&d)).unwrap().permissions().mode() & 0o777;
        assert_eq!(dbmode, 0o600);
        open_for_serve(&d).unwrap();
        let _ = std::fs::remove_dir_all(&d);
        assert!(!d.exists());
    }

    #[test]
    fn the_readonly_opener_never_creates_migrates_or_writes() {
        let d = tmp("readonly");
        assert!(
            open_readonly(&d).is_err(),
            "no database: nothing is created"
        );
        assert!(!db_path(&d).exists());
        drop(open_for_admin(&d).unwrap());
        let ro = open_readonly(&d).unwrap();
        assert!(ro.execute("INSERT INTO users (login, lower_login, kind, created_unix) VALUES ('x','x','user',1)", []).is_err(), "writes are refused");
        drop(ro);
        let c = connect(&d).unwrap();
        c.pragma_update(None, "user_version", SCHEMA_VERSION + 1)
            .unwrap();
        drop(c);
        assert!(
            matches!(open_readonly(&d), Err(DbError::Schema(_))),
            "a schema that is not this binary's fails closed"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn connection_settings_are_durable() {
        let d = tmp("pragmas");
        let conn = open_for_admin(&d).unwrap();
        let mode: String = conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        let sync: i64 = conn
            .query_row("PRAGMA synchronous", [], |r| r.get(0))
            .unwrap();
        let fk: i64 = conn
            .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
            .unwrap();
        assert_eq!((mode.as_str(), sync, fk), ("wal", 2, 1)); // 2 = FULL
        drop(conn);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn admin_refuses_a_mismatched_schema_and_serve_a_newer_one() {
        let d = tmp("mismatch");
        drop(open_for_admin(&d).unwrap());
        let conn = connect(&d).unwrap();
        conn.pragma_update(None, "user_version", SCHEMA_VERSION + 1)
            .unwrap();
        drop(conn);
        assert!(matches!(open_for_admin(&d), Err(DbError::Schema(_))));
        assert!(matches!(open_for_serve(&d), Err(DbError::Schema(_))));
        let _ = std::fs::remove_dir_all(&d);
    }
}

#[cfg(test)]
mod perm_tests {
    use super::*;

    #[test]
    fn an_existing_world_readable_dir_is_tightened() {
        let d = std::env::temp_dir().join(format!("scl-forge-db-perm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
        drop(open_for_admin(&d).unwrap());
        assert_eq!(
            std::fs::metadata(&d).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let _ = std::fs::remove_dir_all(&d);
    }
}
