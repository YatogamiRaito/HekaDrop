//! Platform path resolution for `hekadrop-cli`.
//!
//! Shares the same path logic (config, identity, stats, default download directories)
//! with the desktop GUI app to maintain configuration unity, while keeping
//! dependency overhead low (macOS and Linux support subset for headless environments).
//!
//! // TODO(v0.11): extract to shared hekadrop-platform crate.

use std::path::PathBuf;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::process::Command;

/// Platform-default home directory.
#[cfg(not(target_os = "windows"))]
fn home_dir() -> PathBuf {
    std::env::var_os("HOME").map_or_else(|| PathBuf::from("/tmp"), PathBuf::from)
}

/// Fallback home directory for other platforms.
#[cfg(target_os = "windows")]
fn home_dir() -> PathBuf {
    std::env::var_os("USERPROFILE")
        .map_or_else(|| PathBuf::from("C:\\Users\\Default"), PathBuf::from)
}

/// Uygulamanın kalıcı ayar dizini.
///
/// - macOS: `~/Library/Application Support/HekaDrop`
/// - Linux: `$XDG_CONFIG_HOME/HekaDrop` → `~/.config/HekaDrop`
pub(crate) fn config_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        home_dir().join("Library/Application Support/HekaDrop")
    }
    #[cfg(target_os = "linux")]
    {
        if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
            return PathBuf::from(xdg).join("HekaDrop");
        }
        home_dir().join(".config/HekaDrop")
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        home_dir().join(".config/HekaDrop")
    }
}

/// Cihaz kimliği (Ed25519 private key) için disk yolu — `identity.key`.
pub(crate) fn identity_path() -> PathBuf {
    config_dir().join("identity.key")
}

/// Toplam aktarım istatistikleri için disk yolu — `stats.json`.
pub(crate) fn stats_path() -> PathBuf {
    config_dir().join("stats.json")
}

/// Kullanıcı ayarları (advertise / auto-accept / language vs) için disk yolu —
/// `config.json`.
pub(crate) fn config_path() -> PathBuf {
    config_dir().join("config.json")
}

/// Varsayılan indirme klasörü.
///
/// - Linux: `xdg-user-dir DOWNLOAD` → fallback `$HOME/Downloads`
/// - macOS: `$HOME/Downloads`
pub(crate) fn default_download_dir() -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        if let Ok(out) = Command::new("xdg-user-dir").arg("DOWNLOAD").output() {
            if out.status.success() {
                if let Ok(s) = String::from_utf8(out.stdout) {
                    let trimmed = s.trim();
                    if !trimmed.is_empty() {
                        return PathBuf::from(trimmed);
                    }
                }
            }
        }
    }
    home_dir().join("Downloads")
}

/// mDNS / UI için gösterilecek cihaz adı.
pub(crate) fn device_name() -> String {
    if let Ok(v) = std::env::var("HEKADROP_NAME") {
        if !v.is_empty() {
            return v;
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Ok(out) = Command::new("scutil")
            .args(["--get", "ComputerName"])
            .output()
        {
            if let Ok(s) = String::from_utf8(out.stdout) {
                let t = s.trim();
                if !t.is_empty() {
                    return t.to_string();
                }
            }
        }
        "HekaDrop Mac".to_string()
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(h) = std::fs::read_to_string("/etc/hostname") {
            let t = h.trim();
            if !t.is_empty() {
                return format!("HekaDrop {t}");
            }
        }
        if let Ok(out) = Command::new("hostname").output() {
            if let Ok(s) = String::from_utf8(out.stdout) {
                let t = s.trim();
                if !t.is_empty() {
                    return format!("HekaDrop {t}");
                }
            }
        }
        "HekaDrop Linux".to_string()
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        "HekaDrop Device".to_string()
    }
}
