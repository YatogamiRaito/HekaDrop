//! Platformdan bağımsız yardımcılar — config/logs yolları, device adı,
//! dosya/URL açma, panoya kopyalama, otomatik başlatma.
//!
//! Bu modül tek giriş noktasıdır; çağıranlar (`settings`, `stats`, `main`,
//! `connection`, `ui`) platforma göre ayrım yapmaz. Linux portu yeni target'lar
//! eklerken sadece burası genişletilir.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Uygulamanın kalıcı ayar dizini.
///
/// - macOS: `~/Library/Application Support/HekaDrop`
/// - Linux: `$XDG_CONFIG_HOME/HekaDrop` → `~/.config/HekaDrop`
pub fn config_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var_os("HOME").expect("HOME tanımsız");
        return PathBuf::from(home).join("Library/Application Support/HekaDrop");
    }
    #[cfg(not(target_os = "macos"))]
    {
        if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
            return PathBuf::from(xdg).join("HekaDrop");
        }
        let home = std::env::var_os("HOME").expect("HOME tanımsız");
        PathBuf::from(home).join(".config/HekaDrop")
    }
}

/// Log dosyalarının gideceği dizin.
///
/// - macOS: `~/Library/Logs/HekaDrop`
/// - Linux: `$XDG_STATE_HOME/HekaDrop/logs` → `~/.local/state/HekaDrop/logs`
pub fn logs_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var_os("HOME").expect("HOME tanımsız");
        return PathBuf::from(home).join("Library/Logs/HekaDrop");
    }
    #[cfg(not(target_os = "macos"))]
    {
        if let Some(xdg) = std::env::var_os("XDG_STATE_HOME").filter(|v| !v.is_empty()) {
            return PathBuf::from(xdg).join("HekaDrop/logs");
        }
        let home = std::env::var_os("HOME").expect("HOME tanımsız");
        PathBuf::from(home).join(".local/state/HekaDrop/logs")
    }
}

/// Varsayılan indirme klasörü.
///
/// Linux'ta önce `xdg-user-dir DOWNLOAD` denenir; başarısızsa `~/Downloads`.
pub fn default_download_dir() -> PathBuf {
    #[cfg(not(target_os = "macos"))]
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
    let home = std::env::var_os("HOME").expect("HOME tanımsız");
    PathBuf::from(home).join("Downloads")
}

/// mDNS / UI için gösterilecek cihaz adı.
///
/// - macOS: `scutil --get ComputerName`
/// - Linux: `hostname` / `/etc/hostname` → fallback "HekaDrop Linux"
pub fn device_name() -> String {
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
        return "HekaDrop Mac".to_string();
    }

    #[cfg(not(target_os = "macos"))]
    {
        if let Ok(h) = std::fs::read_to_string("/etc/hostname") {
            let t = h.trim();
            if !t.is_empty() {
                return format!("HekaDrop {}", t);
            }
        }
        if let Ok(out) = Command::new("hostname").output() {
            if let Ok(s) = String::from_utf8(out.stdout) {
                let t = s.trim();
                if !t.is_empty() {
                    return format!("HekaDrop {}", t);
                }
            }
        }
        "HekaDrop Linux".to_string()
    }
}

/// Verilen dosyayı/dizini işletim sisteminin varsayılan programıyla açar.
pub fn open_path(path: &Path) {
    #[cfg(target_os = "macos")]
    let tool = "open";
    #[cfg(not(target_os = "macos"))]
    let tool = "xdg-open";
    let _ = Command::new(tool).arg(path).spawn();
}

/// Dosyayı dosya yöneticisinde (Finder / Nautilus) seçili olarak gösterir.
pub fn reveal_path(path: &Path) {
    #[cfg(target_os = "macos")]
    {
        let _ = Command::new("open").arg("-R").arg(path).spawn();
    }
    #[cfg(not(target_os = "macos"))]
    {
        // D-Bus FileManager1 çoğu Linux DE'de mevcut; başarısızsa parent dizini açarız.
        let uri = format!("file://{}", path.display());
        let dbus = Command::new("dbus-send")
            .args([
                "--session",
                "--dest=org.freedesktop.FileManager1",
                "--type=method_call",
                "/org/freedesktop/FileManager1",
                "org.freedesktop.FileManager1.ShowItems",
                &format!("array:string:{}", uri),
                "string:",
            ])
            .status();
        if matches!(dbus, Ok(s) if s.success()) {
            return;
        }
        let parent = path.parent().unwrap_or(path);
        let _ = Command::new("xdg-open").arg(parent).spawn();
    }
}

/// URL'i tarayıcıda açar.
pub fn open_url(url: &str) {
    #[cfg(target_os = "macos")]
    let tool = "open";
    #[cfg(not(target_os = "macos"))]
    let tool = "xdg-open";
    let _ = Command::new(tool).arg(url).spawn();
}

/// Metni sistem panosuna kopyalar.
///
/// Linux'ta Wayland (wl-copy) ve X11 (xclip/xsel) sırayla denenir.
pub fn copy_to_clipboard(text: &str) {
    use std::io::Write;
    use std::process::Stdio;

    #[cfg(target_os = "macos")]
    let candidates: &[&[&str]] = &[&["pbcopy"]];
    #[cfg(not(target_os = "macos"))]
    let candidates: &[&[&str]] = &[
        &["wl-copy"],
        &["xclip", "-selection", "clipboard"],
        &["xsel", "--clipboard", "--input"],
    ];

    for args in candidates {
        let mut cmd = Command::new(args[0]);
        if args.len() > 1 {
            cmd.args(&args[1..]);
        }
        let child = cmd.stdin(Stdio::piped()).stderr(Stdio::null()).spawn();
        if let Ok(mut c) = child {
            if let Some(stdin) = c.stdin.as_mut() {
                let _ = stdin.write_all(text.as_bytes());
            }
            if let Ok(status) = c.wait() {
                if status.success() {
                    return;
                }
            }
        }
    }
    tracing::warn!(
        "panoya kopyalama başarısız — yardımcı araç (wl-copy/xclip/xsel/pbcopy) bulunamadı"
    );
}
