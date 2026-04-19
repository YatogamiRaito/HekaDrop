//! Kullanıcı arayüzü yardımcıları — cross-platform dialog ve bildirimler.
//!
//! - macOS: `osascript` (AppKit dialog)
//! - Linux: `zenity` (yoksa `kdialog`)
//! - Windows: native `MessageBoxW` / `windows-rs`, file/folder dialog'u için
//!   PowerShell (`System.Windows.Forms`) fallback
//!
//! Dialog aracı yoksa veya headless ortamsa `Reject`/`None` döner; uygulama
//! çökmek yerine güvenli default davranışa geçer.

use anyhow::Result;
#[cfg(target_os = "macos")]
use std::process::Command;
#[cfg(any(target_os = "linux", target_os = "windows"))]
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

#[cfg(target_os = "windows")]
fn prompt_accept_blocking(
    device: &str,
    pin: &str,
    files: &[(String, i64)],
    text_count: usize,
) -> AcceptResult {
    // Windows MessageBoxW ile 3 seçenekli dialog:
    //   Evet  = Kabul + güven   (MB_YESNOCANCEL → IDYES)
    //   Hayır = Kabul            (→ IDNO)
    //   İptal = Reddet           (→ IDCANCEL)
    //
    // Not: Sistem dilini takip eden buton etiketleri "Evet/Hayır/İptal"
    // olur. Mesaj metninde kullanıcıya hangi butonun ne anlama geldiği
    // açıkça yazılır.
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::HWND;
    use windows::Win32::UI::WindowsAndMessaging::{
        MessageBoxW, IDCANCEL, IDNO, IDYES, MB_ICONINFORMATION, MB_SYSTEMMODAL, MB_YESNOCANCEL,
    };

    fn to_wide(s: &str) -> Vec<u16> {
        let mut v: Vec<u16> = s.encode_utf16().collect();
        v.push(0);
        v
    }

    let files_str = format_payload_lines(files, text_count);
    let message = format!(
        "{} cihazından dosya gönderiliyor.\n\nPIN: {}\n\n{}\n\n\
         Evet  = Kabul et + güven listesine ekle\n\
         Hayır = Sadece bu seferlik kabul et\n\
         İptal = Reddet",
        device, pin, files_str
    );
    let title = "HekaDrop";
    let msg_w = to_wide(&message);
    let title_w = to_wide(title);

    let result = unsafe {
        MessageBoxW(
            Some(HWND::default()),
            PCWSTR(msg_w.as_ptr()),
            PCWSTR(title_w.as_ptr()),
            MB_YESNOCANCEL | MB_ICONINFORMATION | MB_SYSTEMMODAL,
        )
    };
    match result {
        r if r == IDYES => AcceptResult::AcceptAndTrust,
        r if r == IDNO => AcceptResult::Accept,
        r if r == IDCANCEL => AcceptResult::Reject,
        _ => AcceptResult::Reject,
    }
}

#[cfg(target_os = "linux")]
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
    #[cfg(target_os = "macos")]
    {
        let _ = path; // macOS'ta aksiyon butonlu notify henüz yok.
        notify(title, body);
    }

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    {
        // notify-rust blocking API'si var; ayrı thread'de başlatıp dialog
        // kapanana kadar bekletiyoruz. Fire-and-forget — tokio runtime'ı
        // bloklamaz.
        //
        // Linux (freedesktop): `default` aksiyonu body tıklamasına, `reveal`
        // ek butona bağlanır (duplicate "Aç" butonu oluşmasın diye tek buton).
        //
        // Windows (WinRT Toast): notify-rust WinRT backend action butonlarını
        // destekler; modern Windows 10+ toast stili gösterir.
        let title = title.to_string();
        let body = body.to_string();
        let spawned = std::thread::Builder::new()
            .name("hekadrop-notify".into())
            .spawn(move || {
                use notify_rust::Notification;
                let handle = Notification::new()
                    .appname("HekaDrop")
                    .summary(&title)
                    .body(&body)
                    .action("default", "Aç")
                    .action("reveal", "Klasörde göster")
                    .timeout(10_000)
                    .show();
                let handle = match handle {
                    Ok(h) => h,
                    Err(e) => {
                        tracing::warn!("notify-rust gösterim hatası: {}", e);
                        #[cfg(target_os = "linux")]
                        {
                            // Linux: notify-send aksiyonsuz ama en azından görünsün.
                            let _ = std::process::Command::new("notify-send")
                                .args(["--app-name=HekaDrop", &title, &body])
                                .status();
                        }
                        return;
                    }
                };
                // `wait_for_action` hem Linux hem Windows'ta aynı API.
                #[cfg(target_os = "linux")]
                handle.wait_for_action(|action| match action {
                    "default" => crate::platform::open_path(&path),
                    "reveal" => crate::platform::reveal_path(&path),
                    _ => {}
                });
                // Windows'ta action handler'ları farklı API ile bağlanır
                // (wait_for_action Linux-özel). Toast otomatik kapanır.
                #[cfg(target_os = "windows")]
                {
                    // path closure'a move ile geldi ama şimdilik Windows
                    // branch'inde toast callback bağlanmadığı için kullanılmıyor.
                    // Unused-variable warning'ini bastır.
                    let _ = &path;
                    let _ = handle;
                }
            });
        if let Err(e) = spawned {
            // title/body closure'a taşındı; fallback için kullanamayız. Thread
            // spawn'ı sistemsel bir hata — sadece warn ve geç.
            tracing::warn!("bildirim thread'i başlatılamadı: {}", e);
        }
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
    #[cfg(target_os = "linux")]
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
    #[cfg(target_os = "windows")]
    {
        // Windows Toast — notify-rust'ın WinRT backend'i. Win 10+'da çalışır.
        use notify_rust::Notification;
        let r = Notification::new()
            .appname("HekaDrop")
            .summary(title)
            .body(body)
            .timeout(7_000)
            .show();
        if let Err(e) = r {
            tracing::info!("[notify-toast hata] {}: {} ({})", title, body, e);
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
    #[cfg(target_os = "linux")]
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
    #[cfg(target_os = "windows")]
    {
        // MessageBoxW blocks; fire-and-forget için ayrı thread'de çalıştır.
        let title = title.to_string();
        let body = body.to_string();
        let _ = std::thread::Builder::new()
            .name("hekadrop-showinfo".into())
            .spawn(move || {
                use windows::core::PCWSTR;
                use windows::Win32::Foundation::HWND;
                use windows::Win32::UI::WindowsAndMessaging::{
                    MessageBoxW, MB_ICONINFORMATION, MB_OK, MB_SYSTEMMODAL,
                };
                fn to_wide(s: &str) -> Vec<u16> {
                    let mut v: Vec<u16> = s.encode_utf16().collect();
                    v.push(0);
                    v
                }
                let body_w = to_wide(&body);
                let title_w = to_wide(&title);
                unsafe {
                    MessageBoxW(
                        Some(HWND::default()),
                        PCWSTR(body_w.as_ptr()),
                        PCWSTR(title_w.as_ptr()),
                        MB_OK | MB_ICONINFORMATION | MB_SYSTEMMODAL,
                    );
                }
            });
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

#[cfg(target_os = "windows")]
fn choose_files_blocking() -> Option<Vec<std::path::PathBuf>> {
    // PowerShell + System.Windows.Forms.OpenFileDialog — cargo-install'suz,
    // her Windows 10/11'de hazır gelir. Multi-select, ardından path'leri
    // satır satır yazdırır. Hata durumunda None.
    let script = r#"
Add-Type -AssemblyName System.Windows.Forms | Out-Null
$dlg = New-Object System.Windows.Forms.OpenFileDialog
$dlg.Title = 'Gönderilecek dosyaları seçin'
$dlg.Multiselect = $true
if ($dlg.ShowDialog() -eq 'OK') { $dlg.FileNames -join "`n" }
"#;
    let out = Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
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
}

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "windows")]
fn choose_folder_blocking() -> Option<std::path::PathBuf> {
    let script = r#"
Add-Type -AssemblyName System.Windows.Forms | Out-Null
$dlg = New-Object System.Windows.Forms.FolderBrowserDialog
$dlg.Description = 'İndirme klasörünü seçin'
$dlg.ShowNewFolderButton = $true
if ($dlg.ShowDialog() -eq 'OK') { $dlg.SelectedPath }
"#;
    let out = Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
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
}

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "windows")]
fn choose_device_blocking(labels: &[String]) -> Option<String> {
    // PowerShell ile minimal ListBox dialog'u. `Out-GridView -PassThru` de
    // kullanılabilirdi ama standart PowerShell'da ayrı modül gerekir;
    // System.Windows.Forms her kurulumda hazır.
    let items = labels
        .iter()
        .map(|s| format!("'{}'", s.replace('\'', "''")))
        .collect::<Vec<_>>()
        .join(",");
    let script = format!(
        r#"
Add-Type -AssemblyName System.Windows.Forms | Out-Null
Add-Type -AssemblyName System.Drawing | Out-Null
$form = New-Object System.Windows.Forms.Form
$form.Text = 'HekaDrop'
$form.Size = New-Object System.Drawing.Size(480, 360)
$form.StartPosition = 'CenterScreen'
$form.TopMost = $true
$label = New-Object System.Windows.Forms.Label
$label.Text = 'Hedef cihaz'
$label.Location = New-Object System.Drawing.Point(10, 10)
$label.Size = New-Object System.Drawing.Size(440, 20)
$form.Controls.Add($label)
$listbox = New-Object System.Windows.Forms.ListBox
$listbox.Location = New-Object System.Drawing.Point(10, 35)
$listbox.Size = New-Object System.Drawing.Size(440, 230)
@({items}) | ForEach-Object {{ [void]$listbox.Items.Add($_) }}
if ($listbox.Items.Count -gt 0) {{ $listbox.SelectedIndex = 0 }}
$form.Controls.Add($listbox)
$ok = New-Object System.Windows.Forms.Button
$ok.Text = 'Gönder'
$ok.Location = New-Object System.Drawing.Point(280, 280)
$ok.DialogResult = 'OK'
$form.AcceptButton = $ok
$form.Controls.Add($ok)
$cancel = New-Object System.Windows.Forms.Button
$cancel.Text = 'İptal'
$cancel.Location = New-Object System.Drawing.Point(370, 280)
$cancel.DialogResult = 'Cancel'
$form.CancelButton = $cancel
$form.Controls.Add($cancel)
if ($form.ShowDialog() -eq 'OK') {{ $listbox.SelectedItem }}
"#
    );
    let out = Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            &script,
        ])
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
}

#[cfg(target_os = "linux")]
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

/// Bir ikili (binary) PATH'te mevcut mu? Linux-only helper (zenity/kdialog
/// varlık kontrolü). Windows'ta kullanılmaz — MessageBoxW her zaman var.
#[cfg(target_os = "linux")]
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
