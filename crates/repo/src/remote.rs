//! `.sc/config` remote configuration (TOML).

use std::collections::BTreeMap;

use crate::error::{Error, Result};
use crate::layout::Layout;

#[derive(serde::Serialize, serde::Deserialize, Default, Debug, Clone)]
pub struct RemoteConfig {
    #[serde(default)]
    pub remote: BTreeMap<String, RemoteEntry>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct RemoteEntry {
    pub url: String,
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
        self.remote.insert(name.to_string(), RemoteEntry { url: url.to_string() });
        Ok(())
    }

    /// The URL configured for `name`, or None if there is no such remote.
    pub fn url(&self, name: &str) -> Option<&str> {
        self.remote.get(name).map(|r| r.url.as_str())
    }

    /// The configured remote names, sorted (the backing map is ordered).
    pub fn names(&self) -> Vec<String> {
        self.remote.keys().cloned().collect()
    }
}
