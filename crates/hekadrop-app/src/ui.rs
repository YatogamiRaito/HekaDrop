//! Kullanıcı arayüzü yardımcıları — cross-platform dialog ve bildirimler.
//!
//! - macOS: `osascript` (`AppKit` dialog)
//! - Linux: `zenity` (yoksa `kdialog`)
//! - Windows: native `MessageBoxW` / `windows-rs`, file/folder dialog'u için
//!   `PowerShell` (`System.Windows.Forms`) fallback
//!
//! Dialog aracı yoksa veya headless ortamsa `Reject`/`None` döner; uygulama
//! çökmek yerine güvenli default davranışa geçer.

use anyhow::Result;
#[cfg(target_os = "macos")]
use std::process::Command;
#[cfg(any(target_os = "linux", target_os = "windows"))]
use std::process::{Command, Stdio};
use tokio::task;

#[expect(
    unused_imports,
    reason = "API: PathBuf cfg-gated platform branch'larında (Linux GTK / macOS / Windows) \
              kullanılıyor; lokal host platform tarafında kullanılmadığı görünebilir."
)]
use std::path::PathBuf;

/// Accept dialog'unda gösterilen tek dosya satırı için minimal özet.
pub(crate) struct FileSummary {
    /// Sanitize edilmemiş görüntülenecek dosya adı (peer'dan).
    pub name: String,
    /// Bayt cinsinden boyut; `human_size()` ile MB/GB formatına çevrilir.
    pub size: i64,
}

/// RFC-0005 PR-F — accept dialog folder enrichment payload.
///
/// Sender peer Introduction'ında `application/x-hekadrop-folder` MIME marker
/// ile bundle gönderdiğinde [`prompt_accept`] çağrısı buna sahip olur ve
/// dialog body'sinde dosya listesi yerine "klasör — N dosya, X" özeti
/// gösterilir.
pub(crate) struct FolderSummary {
    /// Bundle root klasör adı (sanitize edilmiş).
    pub root_name: String,
    /// Bundle içindeki toplam dosya/klasör girişi sayısı.
    pub entry_count: u32,
    /// Bundle uncompressed toplam boyutu (bayt).
    pub total_size: i64,
}

/// `prompt_accept` sonucu — kullanıcı dialog'da hangi butona bastı.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AcceptResult {
    /// Kullanıcı reddetti veya dialog kapandı.
    Reject,
    /// Kullanıcı kabul etti (tek seferlik).
    Accept,
    /// Kullanıcı kabul etti + cihazı trust listesine ekledi.
    AcceptAndTrust,
}

/// Kullanıcıya PIN + dosya listesi gösterir. 3 seçenek döner:
///   - Reddet
///   - Kabul et
///   - Kabul + güven (`device_name` ileride otomatik kabul edilir)
///
/// `folder` `Some` iken peer bundle gönderiyor (RFC-0005 PR-F); dosya listesi
/// yerine `prompt.folder_accept.body` çevrim'i ile zenginleştirilmiş satır
/// gösterilir.
pub(crate) async fn prompt_accept(
    device_name: &str,
    pin_code: &str,
    files: &[FileSummary],
    text_count: usize,
    folder: Option<&FolderSummary>,
) -> Result<AcceptResult> {
    // Peer-kontrollü alanları dialog gövdesine yerleştirmeden önce
    // control karakterleri (özellikle `\n`, `\r`) strip et — kötü niyetli
    // peer'ın dialog metnini manipüle etmesini ve dosya listesi / PIN
    // satırlarını sahte şekilde bozmasını engelle.
    let device = sanitize_field(device_name);
    let pin = sanitize_field(pin_code);
    let files: Vec<(String, i64)> = files
        .iter()
        .map(|f| (sanitize_field(&f.name), f.size))
        .collect();
    // RFC-0005 PR-F: root_name peer-controlled — sender'da
    // sanitize_root_name'den geçti ama UI display öncesi defansif bir kez
    // daha control char strip.
    let folder_owned = folder.map(|f| FolderSummary {
        root_name: sanitize_field(&f.root_name),
        entry_count: f.entry_count,
        total_size: f.total_size,
    });

    task::spawn_blocking(move || {
        prompt_accept_blocking(&device, &pin, &files, text_count, folder_owned.as_ref())
    })
    .await
    .map_err(|e| anyhow::anyhow!("UI task join: {e}"))
}

/// Tek bir peer-kontrollü alan (cihaz adı, dosya adı, PIN) için sıkı
/// sanitize: tüm control karakterler + DEL + C1 strip edilir — `\n`
/// dahil. Alanları dialog mesajına yerleştirmeden önce çalışmalı ki
/// attacker body'yi manipüle edemesin (ör. "evil\nAccepted").
///
/// NOT: `Command::arg()` execve tabanlıdır (shell yok); bu sanitize
/// var olan injection guard'ına ek bir UX-safety katmanıdır.
fn sanitize_field(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).collect()
}

/// Tüm mesaj gövdesi için yumuşak sanitize: `\n` ve `\t` korunur
/// (dosya listesi newline ile ayrılıyor). Geri kalan C0 kontrolleri,
/// DEL (U+007F) ve C1 kontrolleri (U+0080..U+009F) strip edilir.
fn sanitize_display_text(s: &str) -> String {
    s.chars()
        .filter(|c| *c == '\n' || *c == '\t' || !c.is_control())
        .collect()
}

/// Dialog body'sinde gösterilecek dosya/klasör/text özet satırını üretir;
/// sıra: folder summary → text-only count → bullet'lı dosya listesi → "boş".
fn format_payload_lines(
    files: &[(String, i64)],
    text_count: usize,
    folder: Option<&FolderSummary>,
) -> String {
    // RFC-0005 PR-F: bundle MIME marker → "klasör — N dosya, X" satırı
    // dosya listesinin önüne. Folder summary mevcutken peer'ın gerçek payload
    // semantiği "tek bundle" (bundle_name `<root>.hekabundle` summaries'in
    // içinde dosya gibi görünüyor — kullanıcıya "klasör" olarak sunuyoruz ki
    // dağılım/extract şeffaf kalsın).
    if let Some(f) = folder {
        return crate::i18n::tf(
            "prompt.folder_accept.body",
            &[
                &f.root_name,
                &f.entry_count.to_string(),
                &human_size(f.total_size),
            ],
        );
    }
    if files.is_empty() {
        if text_count > 0 {
            crate::i18n::tf("accept.text_count", &[&text_count.to_string()])
        } else {
            crate::i18n::t("accept.content_none").to_string()
        }
    } else {
        files
            .iter()
            .map(|(n, s)| format!("• {} ({})", n, human_size(*s)))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// macOS sürümü — `osascript` `display dialog` ile 3-buton accept prompt;
/// stdout `button returned:<LABEL>` parse edilir.
#[cfg(target_os = "macos")]
fn prompt_accept_blocking(
    device: &str,
    pin: &str,
    files: &[(String, i64)],
    text_count: usize,
    folder: Option<&FolderSummary>,
) -> AcceptResult {
    let files_str = format_payload_lines(files, text_count, folder);
    let message = crate::i18n::tf("accept.body", &[device, pin, &files_str]);
    let btn_reject = crate::i18n::t("accept.reject");
    let btn_accept = crate::i18n::t("accept.accept");
    let btn_trust = crate::i18n::t("accept.accept_trust");
    let title = crate::i18n::t("accept.title");

    // Kullanıcıdan (peer'dan) gelen `device` ve dosya adları AppleScript
    // stringine escape_applescript ile giriyor; ek olarak control char
    // (newline / \r / NUL / DEL) strip için sanitize ediliyor.
    let script = format!(
        r#"display dialog "{}" buttons {{"{}", "{}", "{}"}} default button "{}" cancel button "{}" with title "{}" with icon note"#,
        escape_applescript(&sanitize_display_text(&message)),
        escape_applescript(btn_reject),
        escape_applescript(btn_accept),
        escape_applescript(btn_trust),
        escape_applescript(btn_accept),
        escape_applescript(btn_reject),
        escape_applescript(title),
    );
    let out = Command::new("osascript").arg("-e").arg(&script).output();
    match out {
        Ok(o) => {
            let s = String::from_utf8_lossy(&o.stdout);
            // osascript çıktısı: "button returned:<LABEL>, gave up:false"
            // formatındadır. Önce "button returned:" prefix'li satırı tam
            // olarak ayıklayıp, sonra standart ", gave up:false" suffix'ini
            // `trim_end_matches` ile temizle. Label içinde virgül olabilir
            // (lokalize "Kabul, ve Devam Et" gibi) — `split(',')` kullansak
            // bozulurdu. `==` ile karşılaştırma substring çakışmalarını
            // ("Kabul" ⊂ "Kabul + güven") elimine eder.
            let result_line = s
                .lines()
                .find_map(|l| l.strip_prefix("button returned:"))
                .unwrap_or("");
            let label = result_line.trim_end_matches(", gave up:false").trim();
            if label == btn_trust {
                AcceptResult::AcceptAndTrust
            } else if label == btn_accept {
                AcceptResult::Accept
            } else {
                AcceptResult::Reject
            }
        }
        Err(_) => AcceptResult::Reject,
    }
}

/// Windows sürümü — Win32 `MessageBoxW` 3-buton accept prompt; return value
/// `IDYES` / `IDNO` / `IDCANCEL` map'lenir.
#[cfg(target_os = "windows")]
fn prompt_accept_blocking(
    device: &str,
    pin: &str,
    files: &[(String, i64)],
    text_count: usize,
    folder: Option<&FolderSummary>,
) -> AcceptResult {
    // Windows MessageBoxW ile 3 seçenekli dialog:
    //   Evet  = Kabul + güven   (MB_YESNOCANCEL → IDYES)
    //   Hayır = Kabul            (→ IDNO)
    //   İptal = Reddet           (→ IDCANCEL)
    //
    // Not: Sistem dilini takip eden buton etiketleri "Evet/Hayır/İptal"
    // olur. Mesaj metninde kullanıcıya hangi butonun ne anlama geldiği
    // açıkça yazılır.
    use crate::platform::win::to_wide;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::HWND;
    use windows::Win32::UI::WindowsAndMessaging::{
        MessageBoxW, IDCANCEL, IDNO, IDYES, MB_ICONINFORMATION, MB_SYSTEMMODAL, MB_YESNOCANCEL,
    };

    let files_str = format_payload_lines(files, text_count, folder);
    // MessageBoxW'un Yes/No/Cancel butonları Windows sistem diline göre
    // zaten lokalize geliyor; biz mesajın gövdesinde buton anlamlarını
    // i18n üzerinden yazdırıyoruz.
    let body_main = crate::i18n::tf("accept.body", &[device, pin, &files_str]);
    // Windows sistem Yes/No/Cancel butonları dile göre lokalize olarak geliyor;
    // kullanıcıya sadece hangi butonun hangi aksiyona karşılık geldiğini
    // yazıyoruz. "Kabul + güven" zaten accept+trust semantik bütününü taşıyor.
    //
    // Alternatif: inline C# (Add-Type + WinForms) ile custom 3-label
    // button form. Kod hacmi ve PowerShell boot latency'si nedeniyle
    // mevcut simple-mapping tercih edildi — body'de açık Yes/No/Cancel
    // ↔ anlam eşleştirmesi var.
    let hint = format!(
        "\n\nYes/Evet  = {}\nNo/Hayır = {}\nCancel/İptal = {}",
        crate::i18n::t("accept.accept_trust"),
        crate::i18n::t("accept.accept"),
        crate::i18n::t("accept.reject"),
    );
    let message = sanitize_display_text(&format!("{body_main}{hint}"));
    let title = crate::i18n::t("accept.title");
    let msg_w = to_wide(&message);
    let title_w = to_wide(title);

    // SAFETY: `MessageBoxW`
    // (MSDN: learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messageboxw)
    // - `msg_w` and `title_w` are local `Vec<u16>`s built by `to_wide`,
    //   NUL-terminated, alive for the whole synchronous call (dropped at
    //   end of scope after `MessageBoxW` returns).
    // - `PCWSTR(msg_w.as_ptr())`/`PCWSTR(title_w.as_ptr())` are read at
    //   most up to the embedded NUL.
    // - `HWND::default()` (NULL parent) is documented as valid; the box
    //   becomes a top-level dialog. `MB_SYSTEMMODAL` is set so OS owns
    //   focus serialisation.
    // - Return is the user's button choice (`MESSAGEBOX_RESULT`),
    //   inspected below; no pointer escapes.
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

/// Linux sürümü — `zenity` veya `kdialog` ile 3-buton accept prompt; her
/// ikisi de yoksa `notify-rust` ile bilgilendirip reddet.
#[cfg(target_os = "linux")]
fn prompt_accept_blocking(
    device: &str,
    pin: &str,
    files: &[(String, i64)],
    text_count: usize,
    folder: Option<&FolderSummary>,
) -> AcceptResult {
    let files_str = format_payload_lines(files, text_count, folder);
    let message =
        sanitize_display_text(&crate::i18n::tf("accept.body", &[device, pin, &files_str]));
    let title = crate::i18n::t("accept.title");
    let lbl_accept = crate::i18n::t("accept.accept");
    let lbl_reject = crate::i18n::t("accept.reject");
    let lbl_trust = crate::i18n::t("accept.accept_trust");

    // GÜVENLİK NOTU: tüm dış komutlar `Command::new(bin).args([...])`
    // yani execve ile çalışır — araya shell girmez, peer'dan gelen
    // string'ler argüman olarak direkt parametre alanına gider, command
    // injection yüzeyi yok. Yine de peer-kontrollü alanlar üstte
    // `sanitize_field` ile control char'dan arındırılıyor.
    if have("zenity") {
        // 3-button tek-adım: OK = Accept, Cancel/X = Reject,
        // `--extra-button` = AcceptAndTrust.
        //
        // `--extra-button` zenity ≥3.0'da var (Debian 10+/Ubuntu 18.04+
        // ve tüm güncel dağıtımlar). Basılınca exit code 1 ile çıkar ve
        // label'ı stdout'a yazar — cancel/X'te stdout boş gelir, böylece
        // ikisini ayırt edebiliyoruz.
        //
        // Graceful fallback: extra-button desteği yoksa (zenity 2.x),
        // `zenity_supports_extra_button()` bunu `--version` ile tespit
        // edip iki-adımlı klasik akışa (accept → trust?) düşer.
        if zenity_supports_extra_button() {
            let out = Command::new("zenity")
                .args([
                    "--question",
                    &format!("--title={title}"),
                    &format!("--text={message}"),
                    &format!("--ok-label={lbl_accept}"),
                    &format!("--cancel-label={lbl_reject}"),
                    &format!("--extra-button={lbl_trust}"),
                    "--width=420",
                ])
                .stderr(Stdio::null())
                .output();
            match out {
                Ok(o) if o.status.success() => AcceptResult::Accept,
                Ok(o) => {
                    let stdout = String::from_utf8_lossy(&o.stdout);
                    let line = stdout.trim();
                    if line == lbl_trust {
                        AcceptResult::AcceptAndTrust
                    } else {
                        // Cancel / X / pencere kapatma.
                        AcceptResult::Reject
                    }
                }
                Err(_) => AcceptResult::Reject,
            }
        } else {
            // Eski zenity (< 3.0): iki-adım. Önce accept/reject, kabul
            // edilirse trust sor. UX biraz daha diyalog ağırlıklı ama
            // fonksiyonel paritesi korunuyor.
            let accept = Command::new("zenity")
                .args([
                    "--question",
                    &format!("--title={title}"),
                    &format!("--text={message}"),
                    &format!("--ok-label={lbl_accept}"),
                    &format!("--cancel-label={lbl_reject}"),
                    "--width=420",
                ])
                .stderr(Stdio::null())
                .status();
            if !matches!(accept, Ok(s) if s.success()) {
                return AcceptResult::Reject;
            }
            let trust = Command::new("zenity")
                .args([
                    "--question",
                    &format!("--title={title}"),
                    &format!(
                        "--text={}",
                        sanitize_display_text(&crate::i18n::tf("accept.trust_prompt", &[device]))
                    ),
                    &format!("--ok-label={}", crate::i18n::t("accept.trust_yes")),
                    &format!("--cancel-label={}", crate::i18n::t("accept.trust_later")),
                ])
                .stderr(Stdio::null())
                .status();
            if matches!(trust, Ok(s) if s.success()) {
                AcceptResult::AcceptAndTrust
            } else {
                AcceptResult::Accept
            }
        }
    } else if have("kdialog") {
        // kdialog 3-button: --yesnocancel → Evet (Accept+Trust) / Hayır (Accept) / İptal (Reject)
        let hint = format!(
            "{} / {} / {}",
            crate::i18n::t("accept.accept_trust"),
            crate::i18n::t("accept.accept"),
            crate::i18n::t("accept.reject"),
        );
        let out = Command::new("kdialog")
            .args([
                "--title",
                title,
                "--yesnocancel",
                &format!("{message}\n\n({hint})"),
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
pub(crate) fn notify_file_received(title: &str, body: &str, path: std::path::PathBuf) {
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
        #[cfg(target_os = "linux")]
        let spawned = std::thread::Builder::new()
            .name("hekadrop-notify".into())
            .spawn(move || {
                use notify_rust::Notification;
                let handle = match Notification::new()
                    .appname("HekaDrop")
                    .summary(&title)
                    .body(&body)
                    .action("default", "Aç")
                    .action("reveal", "Klasörde göster")
                    .timeout(10_000)
                    .show()
                {
                    Ok(h) => h,
                    Err(e) => {
                        tracing::warn!("notify-rust gösterim hatası: {}", e);
                        // Linux: notify-send aksiyonsuz ama en azından görünsün.
                        let _ = std::process::Command::new("notify-send")
                            .args(["--app-name=HekaDrop", &title, &body])
                            .status();
                        return;
                    }
                };
                handle.wait_for_action(|action| match action {
                    "default" => crate::platform::open_path(&path),
                    "reveal" => crate::platform::reveal_path(&path),
                    _ => {}
                });
            });

        // Windows: notify-rust WinRT backend toast'ı aksiyon butonu ile
        // render edebilir ama callback/activation mekanizması bu crate
        // sürümünde expose edilmediği için buton tıklaması Rust tarafına
        // iletilmiyor. Ölü buton göstermemek için düz bildirim tercih
        // ediliyor; COM activation ile bağlantı ileride eklenebilir.
        #[cfg(target_os = "windows")]
        let spawned = std::thread::Builder::new()
            .name("hekadrop-notify".into())
            .spawn(move || {
                use notify_rust::Notification;
                let _ = &path; // ileride callback için korunuyor
                if let Err(e) = Notification::new()
                    .appname("HekaDrop")
                    .summary(&title)
                    .body(&body)
                    .timeout(10_000)
                    .show()
                {
                    tracing::warn!("notify-rust gösterim hatası: {}", e);
                }
            });

        if let Err(e) = spawned {
            tracing::warn!("bildirim thread'i başlatılamadı: {}", e);
        }
    }
}

/// Kısa bildirim. Başarı/hata mesajları için.
pub(crate) fn notify(title: &str, body: &str) {
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

/// Fatal (ölümcül) hata diyaloğu — **blocking**. Uygulama başlatılamıyor ve
/// process yakında `exit(1)` çağıracağında kullanıcıya görsel bir açıklama
/// vermek için kullanılır; `show_info` fire-and-forget olduğundan o hata
/// mesajı okunamadan uygulama kapanırdı. Burada `status()` kullanıyoruz →
/// osascript/zenity/MessageBox kapanana kadar thread bloke olur.
///
/// Dialog aracı yoksa (headless) sadece log'a yazılır — zaten log dosyası
/// da açılamamış olabilir, ama `tracing` stdout layer'ı çalışmaya devam eder.
pub(crate) fn fatal_error_dialog(title: &str, body: &str) {
    tracing::error!("fatal: {} — {}", title, body);
    #[cfg(target_os = "macos")]
    {
        let script = format!(
            r#"display dialog "{}" buttons {{"Tamam"}} default button "Tamam" with title "{}" with icon stop"#,
            escape_applescript(body),
            escape_applescript(title)
        );
        let _ = Command::new("osascript").arg("-e").arg(&script).status();
    }
    #[cfg(target_os = "linux")]
    {
        if have("zenity") {
            let _ = Command::new("zenity")
                .args([
                    "--error",
                    &format!("--title={title}"),
                    &format!("--text={body}"),
                    "--width=420",
                ])
                .stderr(Stdio::null())
                .status();
        } else if have("kdialog") {
            let _ = Command::new("kdialog")
                .args(["--title", title, "--error", body])
                .status();
        } else {
            #[expect(
                clippy::print_stderr,
                reason = "HUMAN: Dialog yoksa stderr'e düş — headless / VM / SSH ortamlarında \
                          en azından kullanıcı terminalde fatal mesajı görür. Tracing \
                          henüz initialize olmamış olabilir (startup-fatal)."
            )]
            {
                eprintln!("[HekaDrop] {title}: {body}");
            }
        }
    }
    #[cfg(target_os = "windows")]
    {
        use crate::platform::win::to_wide;
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::HWND;
        use windows::Win32::UI::WindowsAndMessaging::{
            MessageBoxW, MB_ICONERROR, MB_OK, MB_SYSTEMMODAL,
        };
        let body_w = to_wide(body);
        let title_w = to_wide(title);
        // Startup path'te — thread spawn etmeden main thread'de blokla.
        // SAFETY: `MessageBoxW`
        // (MSDN: learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messageboxw)
        // - `body_w` and `title_w` are local NUL-terminated `Vec<u16>`s
        //   alive for the synchronous `MessageBoxW` call (dropped at end
        //   of scope after return).
        // - PCWSTR pointers are read at most up to the NUL.
        // - NULL parent HWND (`HWND::default()`) is documented valid for
        //   top-level dialogs.
        // - Return value (button id) is intentionally discarded — caller
        //   only cares that the user has been informed.
        unsafe {
            MessageBoxW(
                Some(HWND::default()),
                PCWSTR(body_w.as_ptr()),
                PCWSTR(title_w.as_ptr()),
                MB_OK | MB_ICONERROR | MB_SYSTEMMODAL,
            );
        }
    }
}

/// Bilgi diyaloğu (blocking değil, fire-and-forget).
pub(crate) fn show_info(title: &str, body: &str) {
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
                    &format!("--title={title}"),
                    &format!("--text={body}"),
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
                use crate::platform::win::to_wide;
                use windows::core::PCWSTR;
                use windows::Win32::Foundation::HWND;
                use windows::Win32::UI::WindowsAndMessaging::{
                    MessageBoxW, MB_ICONINFORMATION, MB_OK, MB_SYSTEMMODAL,
                };
                let body_w = to_wide(&body);
                let title_w = to_wide(&title);
                // SAFETY: `MessageBoxW`
                // (MSDN: learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messageboxw)
                // - `body_w` and `title_w` are local NUL-terminated
                //   `Vec<u16>`s owned by THIS spawned thread's closure;
                //   they live until the synchronous `MessageBoxW` returns
                //   (closure scope outlasts the call).
                // - PCWSTR pointers are read at most up to the NUL.
                // - NULL parent HWND is documented valid for top-level
                //   dialogs.
                // - Each `show_info` call spawns a fresh thread, so each
                //   buffer pair is owned uniquely; no cross-thread
                //   aliasing.
                // - Return value discarded (fire-and-forget semantics).
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
#[expect(
    dead_code,
    reason = "single-file API helper; UI'da çoklu seçim default, single-pick gelecek toggle için reservoir"
)]
/// Tek dosya seçim dialog'u — `choose_files`'in ilk öğesini döner.
pub(crate) async fn choose_file() -> Option<std::path::PathBuf> {
    choose_files().await.and_then(|mut v| v.pop())
}

/// Çoklu dosya seçim dialog'u → seçilen tüm path'lerin listesi.
pub(crate) async fn choose_files() -> Option<Vec<std::path::PathBuf>> {
    task::spawn_blocking(choose_files_blocking)
        .await
        .ok()
        .flatten()
}

/// macOS sürümü — `osascript` `choose file with multiple selections allowed` ile çoklu dosya seçimi.
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
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(std::path::PathBuf::from)
        .collect();
    if paths.is_empty() {
        None
    } else {
        Some(paths)
    }
}

/// Windows sürümü — Win32 `IFileOpenDialog` `FOS_ALLOWMULTISELECT` ile çoklu dosya seçimi.
#[cfg(target_os = "windows")]
fn choose_files_blocking() -> Option<Vec<std::path::PathBuf>> {
    // PowerShell + System.Windows.Forms.OpenFileDialog — cargo-install'suz,
    // her Windows 10/11'de hazır gelir. Multi-select, ardından path'leri
    // satır satır yazdırır. Hata durumunda None.
    let script = r#"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
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
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(std::path::PathBuf::from)
        .collect();
    if paths.is_empty() {
        None
    } else {
        Some(paths)
    }
}

/// Linux sürümü — `zenity` (öncelik) veya `kdialog` ile çoklu dosya seçimi.
#[cfg(target_os = "linux")]
fn choose_files_blocking() -> Option<Vec<std::path::PathBuf>> {
    let title = crate::i18n::t("send.choose_title");
    if have("zenity") {
        let out = Command::new("zenity")
            .args([
                "--file-selection",
                "--multiple",
                "--separator=\n",
                &format!("--title={title}"),
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
            .map(str::trim)
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
                title,
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
            .map(str::trim)
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
pub(crate) async fn choose_folder() -> Option<std::path::PathBuf> {
    task::spawn_blocking(choose_folder_blocking)
        .await
        .ok()
        .flatten()
}

/// macOS sürümü — `osascript` `choose folder` ile klasör seçimi.
#[cfg(target_os = "macos")]
fn choose_folder_blocking() -> Option<std::path::PathBuf> {
    let prompt = crate::i18n::t("pick.download_folder");
    let script = format!(
        r#"POSIX path of (choose folder with prompt "{}")"#,
        escape_applescript(prompt)
    );
    let out = Command::new("osascript")
        .args(["-e", &script])
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

/// Windows sürümü — Win32 `IFileOpenDialog` `FOS_PICKFOLDERS` ile klasör seçimi.
#[cfg(target_os = "windows")]
fn choose_folder_blocking() -> Option<std::path::PathBuf> {
    // PowerShell'e i18n string'ini güvenli geçirmek için single-quote'ları
    // double'lıyoruz (PS'te single-quoted string içinde `''` → `'`).
    let desc = crate::i18n::t("pick.download_folder").replace('\'', "''");
    let script = format!(
        r"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Add-Type -AssemblyName System.Windows.Forms | Out-Null
$dlg = New-Object System.Windows.Forms.FolderBrowserDialog
$dlg.Description = '{desc}'
$dlg.ShowNewFolderButton = $true
if ($dlg.ShowDialog() -eq 'OK') {{ $dlg.SelectedPath }}
"
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
    let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if path.is_empty() {
        None
    } else {
        Some(std::path::PathBuf::from(path))
    }
}

/// Linux sürümü — `zenity --file-selection --directory` veya `kdialog --getexistingdirectory`.
#[cfg(target_os = "linux")]
fn choose_folder_blocking() -> Option<std::path::PathBuf> {
    let title = crate::i18n::t("pick.download_folder");
    if have("zenity") {
        let out = Command::new("zenity")
            .args([
                "--file-selection",
                "--directory",
                &format!("--title={title}"),
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
            .args(["--title", title, "--getexistingdirectory", "."])
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
pub(crate) async fn choose_device(labels: Vec<String>) -> Option<usize> {
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

/// macOS sürümü — `osascript` `choose from list` ile cihaz seçimi (label döner).
#[cfg(target_os = "macos")]
fn choose_device_blocking(labels: &[String]) -> Option<String> {
    let items = labels
        .iter()
        .map(|s| format!("\"{}\"", escape_applescript(s)))
        .collect::<Vec<_>>()
        .join(", ");
    let script = format!(
        r#"choose from list {{{}}} with prompt "{}" with title "{}" default items {{"{}"}}"#,
        items,
        escape_applescript(crate::i18n::t("send.device_prompt")),
        escape_applescript(crate::i18n::t("app.title")),
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

/// Windows sürümü — basit numbered prompt (gerçek combobox dialog yok).
#[cfg(target_os = "windows")]
fn choose_device_blocking(labels: &[String]) -> Option<String> {
    // PowerShell ile minimal ListBox dialog'u. `Out-GridView -PassThru` de
    // kullanılabilirdi ama standart PowerShell'da ayrı modül gerekir;
    // System.Windows.Forms her kurulumda hazır.
    // PowerShell single-quoted string içinde `''` ile escape ediyoruz
    // (bkz. choose_folder_blocking). i18n string'leri non-ASCII içerebilir;
    // UTF-8 output encoding yukarıda.
    let ps_esc = |s: &str| s.replace('\'', "''");
    let items = labels
        .iter()
        .map(|s| format!("'{}'", ps_esc(s)))
        .collect::<Vec<_>>()
        .join(",");
    let t_title = ps_esc(crate::i18n::t("app.title"));
    let t_prompt = ps_esc(crate::i18n::t("send.device_prompt"));
    let t_send = ps_esc(crate::i18n::t("common.send"));
    let t_cancel = ps_esc(crate::i18n::t("common.cancel"));
    let script = format!(
        r"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Add-Type -AssemblyName System.Windows.Forms | Out-Null
Add-Type -AssemblyName System.Drawing | Out-Null
$form = New-Object System.Windows.Forms.Form
$form.Text = '{t_title}'
$form.Size = New-Object System.Drawing.Size(480, 360)
$form.StartPosition = 'CenterScreen'
$form.TopMost = $true
$label = New-Object System.Windows.Forms.Label
$label.Text = '{t_prompt}'
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
$ok.Text = '{t_send}'
$ok.Location = New-Object System.Drawing.Point(280, 280)
$ok.DialogResult = 'OK'
$form.AcceptButton = $ok
$form.Controls.Add($ok)
$cancel = New-Object System.Windows.Forms.Button
$cancel.Text = '{t_cancel}'
$cancel.Location = New-Object System.Drawing.Point(370, 280)
$cancel.DialogResult = 'Cancel'
$form.CancelButton = $cancel
$form.Controls.Add($cancel)
if ($form.ShowDialog() -eq 'OK') {{ $listbox.SelectedItem }}
"
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

/// Linux sürümü — `zenity --list` veya `kdialog --radiolist` ile cihaz seçimi.
#[cfg(target_os = "linux")]
fn choose_device_blocking(labels: &[String]) -> Option<String> {
    if have("zenity") {
        // zenity --list --radiolist: her satır [TRUE/FALSE, label]
        let mut args: Vec<String> = vec![
            "--list".into(),
            "--radiolist".into(),
            format!("--title={}", crate::i18n::t("app.title")),
            format!("--text={}", crate::i18n::t("send.device_prompt")),
            "--column=".into(),
            format!("--column={}", crate::i18n::t("common.device")),
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
            crate::i18n::t("app.title").into(),
            "--radiolist".into(),
            crate::i18n::t("send.device_prompt").into(),
        ];
        for (i, l) in labels.iter().enumerate() {
            args.push(format!("{i}"));
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
#[expect(
    dead_code,
    reason = "send-side progress notification; sender flow şu an UI port üzerinden, helper future use için tutuldu"
)]
pub(crate) fn send_progress_notify(device: &str, file: &str) {
    notify("HekaDrop", &format!("Gönderiliyor: {file} → {device}"));
}

/// macOS sürümü — `AppleScript` string'i için `\` ve `"` escape eder.
#[cfg(target_os = "macos")]
fn escape_applescript(s: &str) -> String {
    // AppleScript string literal'ında raw newline (`\n`) syntax error verir
    // ve `display dialog` penceresi açılmaz. `sanitize_display_text` mesaj
    // gövdesinde `\n`'leri koruduğu için burada `\r` (AppleScript'in
    // satır sonu karakteri) ile değiştiriyoruz — dialog içinde çok satırlı
    // metin böylece doğru render olur.
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\r")
}

/// zenity `--extra-button` flag'ini destekliyor mu? Versiyon 3.0+'da var.
/// `zenity --version` çıktısı "3.44.0" gibi tek satır; major sayı ≥3 ise
/// true. Hata durumunda (zenity açılmıyor vb.) false — iki-adım fallback.
/// Linux sürümü — `zenity` argümanları için minimal escape (newline strip).
#[cfg(target_os = "linux")]
fn zenity_supports_extra_button() -> bool {
    let out = match Command::new("zenity")
        .arg("--version")
        .stderr(Stdio::null())
        .output()
    {
        Ok(o) if o.status.success() => o.stdout,
        _ => return false,
    };
    let text = String::from_utf8_lossy(&out);
    let major = text
        .trim()
        .split('.')
        .next()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);
    major >= 3
}

/// Bir ikili (binary) PATH'te mevcut mu? Linux-only helper (zenity/kdialog
/// varlık kontrolü). Windows'ta kullanılmaz — `MessageBoxW` her zaman var.
///
/// GÜVENLİK: `sh -c` kullanımı şu an sadece bu dosya içinden sabit
/// binary isimleri ile çağrılıyor ("zenity", "kdialog") — peer-kontrollü
/// veri buraya ulaşmıyor, komut injection riski yok. Yine de defansif
/// olsun diye `bin` içinde shell-special char görürsek direkt `false`
/// dönüyoruz; helper ileride yanlışlıkla dış input ile çağrılırsa da
/// güvenli kalıyor.
/// Linux sürümü — `kdialog` argümanları için minimal escape.
#[cfg(target_os = "linux")]
fn have(bin: &str) -> bool {
    if bin
        .chars()
        .any(|c| !(c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.'))
    {
        return false;
    }
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {bin} >/dev/null 2>&1"))
        .status()
        .is_ok_and(|s| s.success())
}

fn human_size(bytes: i64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    #[expect(
        clippy::cast_precision_loss,
        reason = "HUMAN: byte sayısını okunur birime çevirmek için precision loss kabul."
    )]
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
