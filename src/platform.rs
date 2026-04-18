//! Platformdan bağımsız yardımcılar — config/logs yolları, device adı,
//! dosya/URL açma, panoya kopyalama, otomatik başlatma.
//!
//! Bu modül tek giriş noktasıdır; çağıranlar (`settings`, `stats`, `main`,
//! `connection`, `ui`) platforma göre ayrım yapmaz. Linux portu yeni target'lar
//! eklerken sadece burası genişletilir.

use std::path::{Path, PathBuf};
use std::process::Command;

/// `$HOME` değerini al; tanımlı değilse `/tmp` fallback (macOS/Linux'ta
/// pratikte gerçekleşmez ama daemon/systemd ortamlarında tekil bir senaryo
/// olabilir — panic yerine degraded mode'a düşmek daha sağlıklı).
fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"))
}

/// Uygulamanın kalıcı ayar dizini.
///
/// - macOS: `~/Library/Application Support/HekaDrop`
/// - Linux: `$XDG_CONFIG_HOME/HekaDrop` → `~/.config/HekaDrop`
pub fn config_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        home_dir().join("Library/Application Support/HekaDrop")
    }
    #[cfg(not(target_os = "macos"))]
    {
        if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
            return PathBuf::from(xdg).join("HekaDrop");
        }
        home_dir().join(".config/HekaDrop")
    }
}

/// Log dosyalarının gideceği dizin.
///
/// - macOS: `~/Library/Logs/HekaDrop`
/// - Linux: `$XDG_STATE_HOME/HekaDrop/logs` → `~/.local/state/HekaDrop/logs`
pub fn logs_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        home_dir().join("Library/Logs/HekaDrop")
    }
    #[cfg(not(target_os = "macos"))]
    {
        if let Some(xdg) = std::env::var_os("XDG_STATE_HOME").filter(|v| !v.is_empty()) {
            return PathBuf::from(xdg).join("HekaDrop/logs");
        }
        home_dir().join(".local/state/HekaDrop/logs")
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
    home_dir().join("Downloads")
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
        "HekaDrop Mac".to_string()
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
        // RFC 3986: file:// URI'sinde boşluk / `#` / `?` / `%` / non-ASCII vb.
        // karakterler percent-encode edilmeli — aksi halde URI parse'ı bozulur
        // ve Nautilus dosyayı bulamaz.
        let uri = path_to_file_uri(path);
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

/// Bir dosya yolunu `file://` URI'sine çevirir (RFC 3986 percent-encoding).
///
/// Kaçmadan bırakılanlar: unreserved karakterler (`A-Z a-z 0-9 - . _ ~`)
/// ve path ayırıcı `/`. Diğer her şey — boşluk, `#`, `?`, `%`, Türkçe karakter
/// vb. — `%XX` olarak kodlanır. Bayt seviyesinde çalışır; UTF-8 sequence'ları
/// doğru biçimde kodlanır.
#[cfg(not(target_os = "macos"))]
fn path_to_file_uri(path: &Path) -> String {
    let bytes = path.as_os_str().as_encoded_bytes();
    let mut out = String::from("file://");
    for &b in bytes {
        let unreserved = matches!(b,
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/'
        );
        if unreserved {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

#[cfg(all(test, not(target_os = "macos")))]
mod tests {
    use super::*;

    #[test]
    fn uri_basit_path_kodlamadan_gecer() {
        assert_eq!(
            path_to_file_uri(Path::new("/home/user/file.pdf")),
            "file:///home/user/file.pdf"
        );
    }

    #[test]
    fn uri_bosluklu_dosya_adi_percent_encode() {
        assert_eq!(
            path_to_file_uri(Path::new("/home/user/my file.pdf")),
            "file:///home/user/my%20file.pdf"
        );
    }

    #[test]
    fn uri_hash_ve_soru_isareti_encode() {
        // `#` fragment, `?` query ayırıcısı olarak yorumlanacağından kodlanmalı.
        assert_eq!(
            path_to_file_uri(Path::new("/tmp/a#b?c.txt")),
            "file:///tmp/a%23b%3Fc.txt"
        );
    }

    #[test]
    fn uri_yuzde_isareti_kendisi_de_encode() {
        assert_eq!(
            path_to_file_uri(Path::new("/tmp/%20raw.txt")),
            "file:///tmp/%2520raw.txt"
        );
    }

    #[test]
    fn uri_turkce_karakterler_utf8_bayt_encode() {
        // "şarkı" → UTF-8: 0xC5 0x9F 0x61 0x72 0x6B 0xC4 0xB1
        let uri = path_to_file_uri(Path::new("/müzik/şarkı.mp3"));
        assert_eq!(uri, "file:///m%C3%BCzik/%C5%9Fark%C4%B1.mp3");
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
