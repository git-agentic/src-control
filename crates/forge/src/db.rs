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
