//! Kullanıcı arayüzü yardımcıları — cross-platform dialog ve bildirimler.
//!
//! macOS'ta `osascript` (AppKit dialog'u), Linux'ta `zenity` tercih edilir.
//! Zenity yoksa `kdialog`'a düşer; ikisi de yoksa stderr'e log bırakıp kalıcı
//! başarısızlık yerine "Reject/None" döner — böylece uygulama headless
//! ortamda bile çökmez.
//!
//! tray-icon / objc2 yerine external process tercih edildi çünkü tokio
//! runtime ile sürtünmesi az, tek komutla native dialog açar.

use anyhow::Result;
#[cfg(target_os = "macos")]
use std::process::Command;
#[cfg(not(target_os = "macos"))]
use std::process::{Command, Stdio};
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

    task::spawn_blocking(move || prompt_accept_blocking(&device, &pin, &files, text_count))
        .await
        .map_err(|e| anyhow::anyhow!("UI task join: {}", e))
}

fn format_payload_lines(files: &[(String, i64)], text_count: usize) -> String {
    if files.is_empty() {
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
    }
}

#[cfg(target_os = "macos")]
fn prompt_accept_blocking(
    device: &str,
    pin: &str,
    files: &[(String, i64)],
    text_count: usize,
) -> AcceptResult {
    let files_str = format_payload_lines(files, text_count);
    let message = format!(
        "{} cihazından dosya gönderiliyor.\n\nPIN: {}\n\n{}",
        device, pin, files_str
    );
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
}

#[cfg(not(target_os = "macos"))]
fn prompt_accept_blocking(
    device: &str,
    pin: &str,
    files: &[(String, i64)],
    text_count: usize,
) -> AcceptResult {
    let files_str = format_payload_lines(files, text_count);
    let message = format!(
        "{} cihazından dosya gönderiliyor.\n\nPIN: {}\n\n{}",
        device, pin, files_str
    );

    // zenity yalnız "Tamam/İptal" 2 butonu destekler. "Kabul + güven"
    // seçeneğini ikinci adımda soruyoruz: önce kabul/ret, sonra güven.
    if have("zenity") {
        let accept = Command::new("zenity")
            .args([
                "--question",
                "--title=HekaDrop",
                &format!("--text={}", message),
                "--ok-label=Kabul et",
                "--cancel-label=Reddet",
                "--width=420",
            ])
            .stderr(Stdio::null())
            .status();
        let accepted = matches!(accept, Ok(s) if s.success());
        if !accepted {
            return AcceptResult::Reject;
        }
        let trust = Command::new("zenity")
            .args([
                "--question",
                "--title=HekaDrop",
                &format!("--text={} cihazını bu ve sonraki aktarımlar için güven listesine ekleyeyim mi?", device),
                "--ok-label=Evet, güven",
                "--cancel-label=Sadece bu sefer",
            ])
            .stderr(Stdio::null())
            .status();
        if matches!(trust, Ok(s) if s.success()) {
            AcceptResult::AcceptAndTrust
        } else {
            AcceptResult::Accept
        }
    } else if have("kdialog") {
        // kdialog 3-button: --yesnocancel → Evet (Accept+Trust) / Hayır (Accept) / İptal (Reject)
        let out = Command::new("kdialog")
            .args([
                "--title",
                "HekaDrop",
                "--yesnocancel",
                &format!(
                    "{}\n\n(Evet = Kabul + güven, Hayır = Kabul, İptal = Reddet)",
                    message
                ),
            ])
            .status();
        match out {
            Ok(s) => match s.code() {
                Some(0) => AcceptResult::AcceptAndTrust,
                Some(1) => AcceptResult::Accept,
                _ => AcceptResult::Reject,
            },
            Err(_) => AcceptResult::Reject,
        }
    } else {
        tracing::warn!(
            "prompt_accept: zenity/kdialog yok; aktarım otomatik reddedildi. \
             `sudo apt install zenity` ile kurulum yapın."
        );
        AcceptResult::Reject
    }
}

/// Dosya başarıyla alındıktan sonra gösterilen bildirim.
///
/// Linux'ta "Aç" ve "Klasörde göster" aksiyon butonları eklenir; kullanıcı
/// butona bastığında dosya `xdg-open` ile, klasör ise file-manager ile açılır.
/// macOS'ta aksiyon butonu desteklenmez — düz bildirim + tıklanınca Finder'da
/// açma için fallback uygulanır (bkz. `NotificationCenter` gelecek iş).
pub fn notify_file_received(title: &str, body: &str, path: std::path::PathBuf) {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path; // macOS/Windows: şimdilik plain notify.
        notify(title, body);
        return;
    }

    #[cfg(target_os = "linux")]
    {
        // notify-rust blocking API'si var; ayrı thread'de başlatıp dialog
        // kapanana kadar bekletiyoruz. Fire-and-forget — tokio runtime'ı
        // bloklamaz.
        let title = title.to_string();
        let body = body.to_string();
        std::thread::Builder::new()
            .name("hekadrop-notify".into())
            .spawn(move || {
                use notify_rust::Notification;
                let handle = Notification::new()
                    .appname("HekaDrop")
                    .summary(&title)
                    .body(&body)
                    .action("default", "Aç")
                    .action("open", "Aç")
                    .action("reveal", "Klasörde göster")
                    .timeout(10_000)
                    .show();
                let handle = match handle {
                    Ok(h) => h,
                    Err(e) => {
                        tracing::warn!("notify-rust gösterim hatası: {}", e);
                        // notify-send fallback'i — aksiyonsuz ama en azından görünsün.
                        let _ = std::process::Command::new("notify-send")
                            .args(["--app-name=HekaDrop", &title, &body])
                            .status();
                        return;
                    }
                };
                handle.wait_for_action(|action| match action {
                    "open" | "default" => {
                        crate::platform::open_path(&path);
                    }
                    "reveal" => {
                        crate::platform::reveal_path(&path);
                    }
                    "__closed" => {}
                    _ => {}
                });
            })
            .expect("notify thread spawn");
    }
}

/// Kısa bildirim. Başarı/hata mesajları için.
pub fn notify(title: &str, body: &str) {
    #[cfg(target_os = "macos")]
    {
        let script = format!(
            r#"display notification "{}" with title "{}""#,
            escape_applescript(body),
            escape_applescript(title)
        );
        let _ = Command::new("osascript").arg("-e").arg(&script).spawn();
    }
    #[cfg(not(target_os = "macos"))]
    {
        // notify-send en yaygın; yoksa sessizce log'a yaz.
        let spawned = Command::new("notify-send")
            .args(["--app-name=HekaDrop", title, body])
            .stderr(Stdio::null())
            .spawn();
        if spawned.is_err() {
            tracing::info!("[notify] {}: {}", title, body);
        }
    }
}

/// Bilgi diyaloğu (blocking değil, fire-and-forget).
pub fn show_info(title: &str, body: &str) {
    #[cfg(target_os = "macos")]
    {
        let script = format!(
            r#"display dialog "{}" buttons {{"Tamam"}} default button "Tamam" with title "{}" with icon note"#,
            escape_applescript(body),
            escape_applescript(title)
        );
        let _ = Command::new("osascript").arg("-e").arg(&script).spawn();
    }
    #[cfg(not(target_os = "macos"))]
    {
        if have("zenity") {
            let _ = Command::new("zenity")
                .args([
                    "--info",
                    &format!("--title={}", title),
                    &format!("--text={}", body),
                    "--width=420",
                ])
                .stderr(Stdio::null())
                .spawn();
        } else if have("kdialog") {
            let _ = Command::new("kdialog")
                .args(["--title", title, "--msgbox", body])
                .spawn();
        } else {
            // Dialog yoksa en azından bir masaüstü bildirimi gönder.
            notify(title, body);
        }
    }
}

/// `choose file` dialog → seçilen dosyanın tam yolu veya None (tek dosya).
#[allow(dead_code)]
pub async fn choose_file() -> Option<std::path::PathBuf> {
    choose_files().await.and_then(|mut v| v.pop())
}

/// Çoklu dosya seçim dialog'u → seçilen tüm path'lerin listesi.
pub async fn choose_files() -> Option<Vec<std::path::PathBuf>> {
    task::spawn_blocking(choose_files_blocking)
        .await
        .ok()
        .flatten()
}

#[cfg(target_os = "macos")]
fn choose_files_blocking() -> Option<Vec<std::path::PathBuf>> {
    let script = r#"
set theFiles to choose file with prompt "Gönderilecek dosyaları seçin" with multiple selections allowed
set pathList to ""
repeat with f in theFiles
    set pathList to pathList & (POSIX path of f) & linefeed
end repeat
pathList
"#;
    let out = Command::new("osascript")
        .args(["-e", script])
        .output()
        .ok()?;
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
}

#[cfg(not(target_os = "macos"))]
fn choose_files_blocking() -> Option<Vec<std::path::PathBuf>> {
    if have("zenity") {
        let out = Command::new("zenity")
            .args([
                "--file-selection",
                "--multiple",
                "--separator=\n",
                "--title=Gönderilecek dosyaları seçin",
            ])
            .stderr(Stdio::null())
            .output()
            .ok()?;
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
    } else if have("kdialog") {
        let out = Command::new("kdialog")
            .args([
                "--title",
                "Gönderilecek dosyaları seçin",
                "--getopenfilename",
                "--multiple",
                "--separate-output",
                ".",
            ])
            .output()
            .ok()?;
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
    } else {
        tracing::warn!("choose_files: zenity/kdialog yok");
        None
    }
}

/// `choose folder` dialog → seçilen klasörün path'i.
pub async fn choose_folder() -> Option<std::path::PathBuf> {
    task::spawn_blocking(choose_folder_blocking)
        .await
        .ok()
        .flatten()
}

#[cfg(target_os = "macos")]
fn choose_folder_blocking() -> Option<std::path::PathBuf> {
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
}

#[cfg(not(target_os = "macos"))]
fn choose_folder_blocking() -> Option<std::path::PathBuf> {
    if have("zenity") {
        let out = Command::new("zenity")
            .args([
                "--file-selection",
                "--directory",
                "--title=İndirme klasörünü seçin",
            ])
            .stderr(Stdio::null())
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
    } else if have("kdialog") {
        let out = Command::new("kdialog")
            .args([
                "--title",
                "İndirme klasörünü seçin",
                "--getexistingdirectory",
                ".",
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
    } else {
        None
    }
}

/// Listeden cihaz seçim dialog'u. `labels` içindeki etiket indeks'i döner.
pub async fn choose_device(labels: Vec<String>) -> Option<usize> {
    if labels.is_empty() {
        return None;
    }
    let labels_clone = labels.clone();
    let selected = task::spawn_blocking(move || choose_device_blocking(&labels_clone))
        .await
        .ok()
        .flatten()?;
    labels.iter().position(|l| *l == selected)
}

#[cfg(target_os = "macos")]
fn choose_device_blocking(labels: &[String]) -> Option<String> {
    let items = labels
        .iter()
        .map(|s| format!("\"{}\"", escape_applescript(s)))
        .collect::<Vec<_>>()
        .join(", ");
    let script = format!(
        r#"choose from list {{{}}} with prompt "Hedef cihaz" with title "HekaDrop" default items {{"{}"}}"#,
        items,
        escape_applescript(&labels[0])
    );
    let out = Command::new("osascript")
        .args(["-e", &script])
        .output()
        .ok()?;
    let result = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if result == "false" || result.is_empty() {
        return None;
    }
    Some(result)
}

#[cfg(not(target_os = "macos"))]
fn choose_device_blocking(labels: &[String]) -> Option<String> {
    if have("zenity") {
        // zenity --list --radiolist: her satır [TRUE/FALSE, label]
        let mut args: Vec<String> = vec![
            "--list".into(),
            "--radiolist".into(),
            "--title=HekaDrop".into(),
            "--text=Hedef cihaz".into(),
            "--column=".into(),
            "--column=Cihaz".into(),
            "--width=480".into(),
            "--height=360".into(),
        ];
        for (i, l) in labels.iter().enumerate() {
            args.push(if i == 0 {
                "TRUE".into()
            } else {
                "FALSE".into()
            });
            args.push(l.clone());
        }
        let out = Command::new("zenity")
            .args(&args)
            .stderr(Stdio::null())
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let result = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if result.is_empty() {
            None
        } else {
            Some(result)
        }
    } else if have("kdialog") {
        let mut args: Vec<String> = vec![
            "--title".into(),
            "HekaDrop".into(),
            "--radiolist".into(),
            "Hedef cihaz".into(),
        ];
        for (i, l) in labels.iter().enumerate() {
            args.push(format!("{}", i));
            args.push(l.clone());
            args.push(if i == 0 { "on".into() } else { "off".into() });
        }
        let out = Command::new("kdialog").args(&args).output().ok()?;
        if !out.status.success() {
            return None;
        }
        let idx_str = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let idx: usize = idx_str.parse().ok()?;
        labels.get(idx).cloned()
    } else {
        None
    }
}

/// Dosya keşif sırasında basit bir ilerleme/bildirim dialog'u olmadığı için
/// notify kullanıyoruz.
#[allow(dead_code)]
pub fn send_progress_notify(device: &str, file: &str) {
    notify("HekaDrop", &format!("Gönderiliyor: {} → {}", file, device));
}

#[cfg(target_os = "macos")]
fn escape_applescript(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(not(target_os = "macos"))]
fn have(bin: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {} >/dev/null 2>&1", bin))
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
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
