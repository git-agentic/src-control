//! `.sc/config` remote configuration (TOML).

use std::collections::BTreeMap;

use crate::error::{Error, Result};
use crate::layout::Layout;

#[derive(serde::Serialize, serde::Deserialize, Default, Debug, Clone)]
pub struct RemoteConfig {
    #[serde(default)]
    pub remote: BTreeMap<String, RemoteEntry>,
}

/// Whether a remote is another `sc` repo (object/pack transport) or a Git repo
/// (translated via `gitio`). Defaults to `Sc` so configs written before this
/// field existed still load.
#[derive(serde::Serialize, serde::Deserialize, Default, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RemoteKind {
    #[default]
    Sc,
    Git,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct RemoteEntry {
    pub url: String,
    #[serde(default)]
    pub kind: RemoteKind,
}

impl RemoteConfig {
    /// Load `.sc/config`; missing file => empty config.
    pub fn load(layout: &Layout) -> Result<RemoteConfig> {
        match std::fs::read_to_string(layout.config_path()) {
            Ok(text) => {
                toml::from_str(&text).map_err(|e| Error::BadConfig(format!("bad .sc/config: {e}")))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(RemoteConfig::default()),
            Err(e) => Err(e.into()),
        }
    }

    /// Write `.sc/config`.
    pub fn save(&self, layout: &Layout) -> Result<()> {
        let text = toml::to_string(self).map_err(|e| Error::BadConfig(e.to_string()))?;
        std::fs::write(layout.config_path(), text)?;
        Ok(())
    }

    /// Register a new remote; errors `RemoteExists` if `name` is already set.
    pub fn add(&mut self, name: &str, url: &str) -> Result<()> {
        if self.remote.contains_key(name) {
            return Err(Error::RemoteExists(name.to_string()));
        }
        self.remote.insert(
            name.to_string(),
            RemoteEntry {
                url: url.to_string(),
                kind: RemoteKind::default(),
            },
        );
        Ok(())
    }

    /// Register a new remote of the given kind; errors `RemoteExists` if set.
    pub fn add_kind(&mut self, name: &str, url: &str, kind: RemoteKind) -> Result<()> {
        if self.remote.contains_key(name) {
            return Err(Error::RemoteExists(name.to_string()));
        }
        self.remote.insert(
            name.to_string(),
            RemoteEntry {
                url: url.to_string(),
                kind,
            },
        );
        Ok(())
    }

    /// The URL configured for `name`, or None if there is no such remote.
    pub fn url(&self, name: &str) -> Option<&str> {
        self.remote.get(name).map(|r| r.url.as_str())
    }

    /// The kind configured for `name`, or None if there is no such remote.
    pub fn kind(&self, name: &str) -> Option<RemoteKind> {
        self.remote.get(name).map(|r| r.kind)
    }

    /// The configured remote names, sorted (the backing map is ordered).
    pub fn names(&self) -> Vec<String> {
        self.remote.keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::Layout;

    fn tmp_layout(tag: &str) -> Layout {
        let root = std::env::temp_dir().join(format!("scl-remotecfg-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let layout = Layout::at(&root);
        std::fs::create_dir_all(&layout.dot_sc).unwrap();
        layout
    }

    #[test]
    fn kind_defaults_to_sc_and_git_roundtrips() {
        let layout = tmp_layout("kind");
        let mut cfg = RemoteConfig::default();
        cfg.add("origin", "/path/a").unwrap();
        cfg.add_kind("hub", "/path/b", RemoteKind::Git).unwrap();
        cfg.save(&layout).unwrap();

        let loaded = RemoteConfig::load(&layout).unwrap();
        assert_eq!(loaded.kind("origin"), Some(RemoteKind::Sc));
        assert_eq!(loaded.kind("hub"), Some(RemoteKind::Git));
        assert_eq!(loaded.kind("missing"), None);
        std::fs::remove_dir_all(&layout.root).unwrap();
    }

    #[test]
    fn legacy_config_without_kind_loads_as_sc() {
        let layout = tmp_layout("legacy");
        // A config written before RemoteKind existed: no `kind` key.
        std::fs::write(layout.config_path(), "[remote.origin]\nurl = \"/path/a\"\n").unwrap();
        let loaded = RemoteConfig::load(&layout).unwrap();
        assert_eq!(loaded.kind("origin"), Some(RemoteKind::Sc));
        std::fs::remove_dir_all(&layout.root).unwrap();
    }
}
