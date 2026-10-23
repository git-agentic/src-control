//! `sc-forge admin …`: operate on the data directory directly, no network.
//! Mirrors the `gitea admin` commands Codento Engine's bootstrap scripts call.

use crate::db;
use crate::names;
use crate::store::{self, NewAccount, StoreError, UserPatch};
use crate::timefmt::now;
use anyhow::{anyhow, bail, Result};
use scl_crypto::hash_password;
use std::path::Path;

/// `admin user create`.
pub fn user_create(
    data_dir: &Path,
    username: &str,
    password: &str,
    email: &str,
    admin: bool,
    must_change_password: bool,
) -> Result<()> {
    if password.is_empty() {
        bail!("password must not be empty");
    }
    if names::check(username).is_err() {
        bail!("invalid or reserved username {username:?}");
    }
    let conn = db::open_for_admin(data_dir)?;
    let acct = NewAccount {
        login: username.into(),
        email: email.into(),
        password_hash: hash_password(password),
        must_change_password,
        is_admin: admin,
        visibility: "public".into(),
        ..Default::default()
    };
    match store::create_account(&conn, &acct, now()) {
        Ok(_) => Ok(()),
        Err(StoreError::Exists) => bail!("user already exists [name: {username}]"),
        Err(e) => Err(e.into()),
    }
}

/// `admin user change-password`.
pub fn user_change_password(
    data_dir: &Path,
    username: &str,
    password: &str,
    must_change_password: bool,
) -> Result<()> {
    if password.is_empty() {
        bail!("password must not be empty");
    }
    let conn = db::open_for_admin(data_dir)?;
    let user = store::find_by_login(&conn, username)?
        .filter(|u| !u.is_org)
        .ok_or_else(|| anyhow!("user does not exist [name: {username}]"))?;
    let patch = UserPatch {
        password_hash: Some(hash_password(password)),
        must_change_password: Some(must_change_password),
        ..Default::default()
    };
    store::update_user(&conn, user.id, &patch)?;
    Ok(())
}

/// `admin user generate-access-token`; returns the one-time secret.
pub fn generate_access_token(
    data_dir: &Path,
    username: &str,
    token_name: &str,
    scopes: &[String],
) -> Result<String> {
    let conn = db::open_for_admin(data_dir)?;
    let user = store::find_by_login(&conn, username)?
        .filter(|u| !u.is_org)
        .ok_or_else(|| anyhow!("user does not exist [name: {username}]"))?;
    match store::mint(&conn, user.id, token_name, scopes, now()) {
        Ok((_, secret)) => Ok(secret),
        Err(store::MintError::BadScope(s)) => bail!("invalid access token scope: {s}"),
        Err(store::MintError::Store(StoreError::Exists)) => {
            bail!("access token name has been used already: {token_name}")
        }
        Err(store::MintError::Store(e)) => Err(e.into()),
    }
}

/// `admin org create`.
pub fn org_create(data_dir: &Path, name: &str, owner: &str) -> Result<()> {
    if names::check(name).is_err() {
        bail!("invalid or reserved organization name {name:?}");
    }
    let mut conn = db::open_for_admin(data_dir)?;
    let owner = store::find_by_login(&conn, owner)?
        .filter(|u| !u.is_org)
        .ok_or_else(|| anyhow!("owner does not exist [name: {owner}]"))?;
    let acct = NewAccount {
        login: name.into(),
        is_org: true,
        visibility: "public".into(),
        ..Default::default()
    };
    match store::create_org(&mut conn, &acct, owner.id, now()) {
        Ok(_) => Ok(()),
        Err(StoreError::Exists) => bail!("user already exists [name: {name}]"),
        Err(e) => Err(e.into()),
    }
}
