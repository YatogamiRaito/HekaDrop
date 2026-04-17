//! macOS kullanıcı arayüzü — osascript ile native dialog ve bildirimler.
//!
//! tray-icon / objc2 yerine `osascript` tercih edildi çünkü tokio runtime ile
//! sürtünmesi az, tek komutla native AppKit dialog'u açar.

use anyhow::Result;
use std::process::Command;
use tokio::task;

#[allow(unused_imports)]
use std::path::PathBuf;

pub struct FileSummary {
    pub name: String,
    pub size: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptResult {
    Reject,
    Accept,
    AcceptAndTrust,
}

/// Kullanıcıya PIN + dosya listesi gösterir. 3 seçenek döner:
///   - Reddet
///   - Kabul et
///   - Kabul + güven (device_name ileride otomatik kabul edilir)
pub async fn prompt_accept(
    device_name: &str,
    pin_code: &str,
    files: &[FileSummary],
    text_count: usize,
) -> Result<AcceptResult> {
    let device = device_name.to_string();
    let pin = pin_code.to_string();
    let files: Vec<(String, i64)> = files.iter().map(|f| (f.name.clone(), f.size)).collect();

    task::spawn_blocking(move || {
        let files_str = if files.is_empty() {
            if text_count > 0 {
                format!("{} metin", text_count)
            } else {
                "içerik yok".to_string()
            }
        } else {
            files
                .iter()
                .map(|(n, s)| format!("• {} ({})", n, human_size(*s)))
                .collect::<Vec<_>>()
                .join("\n")
        };

        let message = format!(
            "{} cihazından dosya gönderiliyor.\n\nPIN: {}\n\n{}",
            device, pin, files_str
        );

        // osascript 3 buton destekler. En sağdaki default.
        let script = format!(
            r#"display dialog "{}" buttons {{"Reddet", "Kabul et", "Kabul + güven"}} default button "Kabul et" cancel button "Reddet" with title "HekaDrop" with icon note"#,
            escape_applescript(&message)
        );

        let out = Command::new("osascript").arg("-e").arg(&script).output();
        match out {
            Ok(o) => {
                let s = String::from_utf8_lossy(&o.stdout);
                if s.contains("Kabul + güven") {
                    AcceptResult::AcceptAndTrust
                } else if s.contains("Kabul et") {
                    AcceptResult::Accept
                } else {
                    AcceptResult::Reject
                }
            }
            Err(_) => AcceptResult::Reject,
        }
    })
    .await
    .map_err(|e| anyhow::anyhow!("UI task join: {}", e))
}

/// Kısa bildirim (macOS Notification Center). Başarı/hata mesajları için.
pub fn notify(title: &str, body: &str) {
    let script = format!(
        r#"display notification "{}" with title "{}""#,
        escape_applescript(body),
        escape_applescript(title)
    );
    let _ = Command::new("osascript").arg("-e").arg(&script).spawn();
}

/// Bilgi diyaloğu (blocking değil, fire-and-forget).
pub fn show_info(title: &str, body: &str) {
    let script = format!(
        r#"display dialog "{}" buttons {{"Tamam"}} default button "Tamam" with title "{}" with icon note"#,
        escape_applescript(body),
        escape_applescript(title)
    );
    let _ = Command::new("osascript").arg("-e").arg(&script).spawn();
}

/// `choose file` dialog → seçilen dosyanın tam yolu veya None (tek dosya).
#[allow(dead_code)]
pub async fn choose_file() -> Option<std::path::PathBuf> {
    choose_files().await.and_then(|mut v| v.pop())
}

/// Çoklu dosya seçim dialog'u → seçilen tüm POSIX path'lerin listesi.
pub async fn choose_files() -> Option<Vec<std::path::PathBuf>> {
    task::spawn_blocking(|| {
        let script = r#"
set theFiles to choose file with prompt "Gönderilecek dosyaları seçin" with multiple selections allowed
set pathList to ""
repeat with f in theFiles
    set pathList to pathList & (POSIX path of f) & linefeed
end repeat
pathList
"#;
        let out = Command::new("osascript").args(["-e", script]).output().ok()?;
        if !out.status.success() {
            return None;
        }
        let text = String::from_utf8_lossy(&out.stdout);
        let paths: Vec<_> = text
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty())
            .map(std::path::PathBuf::from)
            .collect();
        if paths.is_empty() {
            None
        } else {
            Some(paths)
        }
    })
    .await
    .ok()
    .flatten()
}

/// `choose folder` dialog → seçilen klasörün POSIX path'i.
pub async fn choose_folder() -> Option<std::path::PathBuf> {
    task::spawn_blocking(|| {
        let out = Command::new("osascript")
            .args([
                "-e",
                r#"POSIX path of (choose folder with prompt "İndirme klasörünü seçin")"#,
            ])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if path.is_empty() {
            None
        } else {
            Some(std::path::PathBuf::from(path))
        }
    })
    .await
    .ok()
    .flatten()
}

/// Listeden cihaz seçim dialog'u. `labels` içindeki etiket indeks'i döner.
pub async fn choose_device(labels: Vec<String>) -> Option<usize> {
    if labels.is_empty() {
        return None;
    }
    let labels_clone = labels.clone();
    let selected = task::spawn_blocking(move || {
        let items = labels_clone
            .iter()
            .map(|s| format!("\"{}\"", escape_applescript(s)))
            .collect::<Vec<_>>()
            .join(", ");
        let script = format!(
            r#"choose from list {{{}}} with prompt "Hedef cihaz" with title "HekaDrop" default items {{"{}"}}"#,
            items,
            escape_applescript(&labels_clone[0])
        );
        let out = Command::new("osascript").args(["-e", &script]).output().ok()?;
        let result = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if result == "false" || result.is_empty() {
            return None;
        }
        Some(result)
    })
    .await
    .ok()
    .flatten()?;

    labels.iter().position(|l| *l == selected)
}

/// Dosya keşif sırasında basit bir ilerleme/bildirim dialog'u olmadığı için
/// notify kullanıyoruz. Dönüş: kullanıcı iptal ederse false, gönderim başladıysa true.
#[allow(dead_code)]
pub fn send_progress_notify(device: &str, file: &str) {
    notify("HekaDrop", &format!("Gönderiliyor: {} → {}", file, device));
}

fn escape_applescript(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn human_size(bytes: i64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut n = bytes as f64;
    let mut i = 0;
    while n >= 1024.0 && i < UNITS.len() - 1 {
        n /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{} {}", bytes, UNITS[i])
    } else {
        format!("{:.1} {}", n, UNITS[i])
    }
}
