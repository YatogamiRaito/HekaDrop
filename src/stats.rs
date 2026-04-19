//! Kalıcı kullanım istatistikleri — platforma göre:
//!   - macOS: `~/Library/Application Support/HekaDrop/stats.json`
//!   - Linux: `~/.config/HekaDrop/stats.json`
//!
//! Her başarılı aktarım sonrası güncellenir. UI'da "Tanı" sekmesinde gösterilir.
//! SystemTime yerine UNIX epoch saniye olarak saklanır (serde'de kolay, taşınabilir).

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeviceStats {
    #[serde(default)]
    pub bytes: u64,
    #[serde(default)]
    pub count: u64,
    #[serde(default)]
    pub last_seen_epoch: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Stats {
    #[serde(default)]
    pub bytes_received: u64,
    #[serde(default)]
    pub bytes_sent: u64,
    #[serde(default)]
    pub files_received: u64,
    #[serde(default)]
    pub files_sent: u64,
    #[serde(default)]
    pub per_device_rx: HashMap<String, DeviceStats>,
    #[serde(default)]
    pub per_device_tx: HashMap<String, DeviceStats>,
    #[serde(default)]
    pub first_use_epoch: u64,
    #[serde(default)]
    pub last_use_epoch: u64,
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl Stats {
    pub fn load() -> Self {
        let path = stats_path();
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str::<Stats>(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) -> Result<()> {
        let path = stats_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let json = serde_json::to_string_pretty(self).context("stats JSON serialize")?;
        // Atomik tmp+rename — crash sırasında yarım yazılmış JSON diske kalmaz.
        crate::settings::atomic_write(&path, json.as_bytes())
            .context("stats.json yazılamadı")?;
        Ok(())
    }

    pub fn record_received(&mut self, device: &str, size: u64) {
        let now = now_epoch();
        if self.first_use_epoch == 0 {
            self.first_use_epoch = now;
        }
        self.last_use_epoch = now;
        self.bytes_received = self.bytes_received.saturating_add(size);
        self.files_received += 1;
        let d = self.per_device_rx.entry(device.to_string()).or_default();
        d.bytes = d.bytes.saturating_add(size);
        d.count += 1;
        d.last_seen_epoch = now;
    }

    pub fn record_sent(&mut self, device: &str, size: u64) {
        let now = now_epoch();
        if self.first_use_epoch == 0 {
            self.first_use_epoch = now;
        }
        self.last_use_epoch = now;
        self.bytes_sent = self.bytes_sent.saturating_add(size);
        self.files_sent += 1;
        let d = self.per_device_tx.entry(device.to_string()).or_default();
        d.bytes = d.bytes.saturating_add(size);
        d.count += 1;
        d.last_seen_epoch = now;
    }

    /// En büyük aktarım hacmine sahip RX cihazı (name, bytes).
    pub fn top_rx_device(&self) -> Option<(String, u64)> {
        self.per_device_rx
            .iter()
            .max_by_key(|(_, s)| s.bytes)
            .map(|(n, s)| (n.clone(), s.bytes))
    }

    pub fn top_tx_device(&self) -> Option<(String, u64)> {
        self.per_device_tx
            .iter()
            .max_by_key(|(_, s)| s.bytes)
            .map(|(n, s)| (n.clone(), s.bytes))
    }
}

fn stats_path() -> PathBuf {
    crate::platform::config_dir().join("stats.json")
}
