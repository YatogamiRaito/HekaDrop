//! Kalıcı ayarlar — `~/Library/Application Support/HekaDrop/config.json`.
//!
//! JSON formatı insan tarafından okunabilir, ileri uyumlu. Bilinmeyen alanlar yok
//! sayılır (`#[serde(default)]`).

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    /// Kullanıcı tarafından atanan görünen ad (boş bırakılırsa `scutil --get ComputerName`).
    #[serde(default)]
    pub device_name: Option<String>,

    /// İndirme dizini (boş bırakılırsa `~/Downloads`).
    #[serde(default)]
    pub download_dir: Option<PathBuf>,

    /// True ise Introduction alındığında kullanıcı onayı istenmeden otomatik kabul edilir.
    /// Güvenliği zayıflatır; varsayılan false.
    #[serde(default)]
    pub auto_accept: bool,

    /// Kullanıcının "Kabul + güven" ile onayladığı cihaz adları. Bu listedeki
    /// isimlerden gelen aktarımlar dialog göstermeden kabul edilir ve rate limiting
    /// uygulanmaz (memory kuralı: trusted cihazlar rate limit dışıdır).
    #[serde(default)]
    pub trusted_devices: Vec<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            device_name: None,
            download_dir: None,
            auto_accept: false,
            trusted_devices: Vec::new(),
        }
    }
}

impl Settings {
    pub fn is_trusted(&self, device_name: &str) -> bool {
        self.trusted_devices.iter().any(|n| n == device_name)
    }

    pub fn add_trusted(&mut self, device_name: &str) {
        if !self.is_trusted(device_name) && !device_name.is_empty() {
            self.trusted_devices.push(device_name.to_string());
        }
    }

    pub fn remove_trusted(&mut self, device_name: &str) {
        self.trusted_devices.retain(|n| n != device_name);
    }
}

impl Settings {
    pub fn load() -> Self {
        let path = config_path();
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str::<Settings>(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) -> Result<()> {
        let path = config_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let json = serde_json::to_string_pretty(self).context("JSON serialize")?;
        std::fs::write(&path, json).context("config.json yazılamadı")?;
        Ok(())
    }

    pub fn resolved_device_name(&self) -> String {
        self.device_name
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(crate::config::device_name)
    }

    pub fn resolved_download_dir(&self) -> PathBuf {
        self.download_dir.clone().unwrap_or_else(|| {
            let home = std::env::var_os("HOME").expect("HOME tanımsız");
            PathBuf::from(home).join("Downloads")
        })
    }
}

pub fn config_path() -> PathBuf {
    let home = std::env::var_os("HOME").expect("HOME tanımsız");
    PathBuf::from(home).join("Library/Application Support/HekaDrop/config.json")
}
