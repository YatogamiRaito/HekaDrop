// Bin'in inline `#[cfg(test)] mod tests` blokları için test-mode allow seti.
// Detay için bkz. `lib.rs` aynı attribute.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::expect_fun_call,
        clippy::panic,
        clippy::print_stdout,
        clippy::print_stderr,
        clippy::redundant_clone,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_lossless,
        clippy::cast_precision_loss,
        clippy::ignored_unit_patterns,
        clippy::use_self,
        clippy::trivially_copy_pass_by_ref,
        clippy::single_match_else,
        clippy::map_err_ignore,
    )
)]

use anyhow::Result;
use std::sync::OnceLock;
use std::time::Duration;
use tao::event::{Event, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoopBuilder};
#[cfg(target_os = "macos")]
use tao::platform::macos::{ActivationPolicy, EventLoopExtMacOS};
use tao::window::WindowBuilder;
use tokio::runtime::Handle;
use tracing::info;
use tray_icon::menu::{CheckMenuItem, Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::TrayIconBuilder;
#[cfg(not(target_os = "linux"))]
use tray_icon::{MouseButton, MouseButtonState, TrayIconEvent};
use wry::{DragDropEvent, WebViewBuilder};

// RFC-0001 §5 Adım 3 — `hekadrop-core` shim'i.
//
// 8 leaf modül artık core'da. `crate::crypto::xxx`, `use crate::error::*` gibi
// in-tree çağrıları korumak için root-level re-export ediyoruz; bu sayede
// `connection.rs`, `sender.rs`, `payload.rs`, vs. dosyalardaki yüzlerce
// import noktası dokunulmadan derlenir. Lib.rs aynı re-export setini taşır.
//
// `payload`, `state`, `discovery`, `mdns`, `i18n`, `identity`, `platform`,
// `settings`, `stats`, `ui` henüz app crate'inde — sonraki RFC adımlarında
// `hekadrop-core` ve `hekadrop-net` arasında ayrılacak.
use hekadrop_core::{config, crypto, error, file_size_guard, frame, log_redact, secure, ukey2};

mod connection;
mod discovery;
mod i18n;
mod identity;
mod mdns;
mod payload;
mod platform;
mod sender;
mod server;
mod settings;
mod state;
mod stats;
mod ui;

static RUNTIME: OnceLock<Handle> = OnceLock::new();

// RFC-0001 §5 Adım 2: protobuf bindings `hekadrop-proto` crate'inden
// re-export ediliyor. `crate::securegcm::...`, `crate::location::...`,
// `crate::sharing::...`, `crate::securemessage::...` çağrıları kod tabanı
// boyunca korunur (yüzlerce import noktası dokunulmaz). Dual-include
// borcu (lib.rs + main.rs aynı bloku yineliyordu) bu adımla kapandı.
pub use hekadrop_proto::{location, securegcm, securemessage, sharing};

// Workspace refactor (v0.7 Step 1): resources/ workspace root'ta kaldı; app
// crate'i crates/hekadrop-app/ altına taşındı → relative path iki seviye yukarı.
const WINDOW_HTML: &str = include_str!("../../../resources/window.html");

async fn async_main() -> Result<()> {
    let device_name = state::get().settings.read().resolved_device_name();
    info!("HekaDrop başlıyor — cihaz: {}", device_name);

    let listener = server::start_listener().await?;
    let port = listener.local_addr()?.port();
    state::set_listen_port(port);
    info!("TCP dinleniyor: 0.0.0.0:{}", port);

    // H#4 privacy control: advertise=false iken LAN'da görünmez ("receive-only"
    // mod). Kullanıcı hâlâ `sender` flow'u ile dosya gönderebilir ama mDNS
    // yayını yapılmadığından Android tarafı bu cihazı listede göstermez.
    // Değişiklik restart gerektirir — mDNS daemon hot-swap henüz yok.
    let advertise_enabled = state::get().settings.read().advertise;
    let _mdns_handle = if advertise_enabled {
        mdns::advertise(&device_name, port)?
    } else {
        info!("mDNS advertise devre dışı (Settings.advertise=false) — receive-only mod");
        None
    };

    tokio::select! {
        res = server::accept_loop(listener) => {
            if let Err(e) = res {
                tracing::error!("accept_loop hata: {:?}", e);
            }
        }
        _ = tokio::signal::ctrl_c() => {
            info!("Ctrl+C — kapatılıyor");
        }
    }

    Ok(())
}

fn main() {
    // H#4 privacy control: log level Settings'ten okunur. `RUST_LOG` env var
    // varsa o öncelikli (geliştirici kaçış vanası). Settings'i logger'dan
    // ÖNCE yüklememiz lazım → state::init'ten önce lokal load yapıp iki
    // kere okumamak için aynı instance'ı state'e taşıyoruz.
    let settings = settings::Settings::load();
    setup_logging(settings.log_level);

    state::init(settings);

    // Issue #17: startup'ta süresi dolmuş trust kayıtlarını temizle. Legacy
    // kayıtlar (epoch>0) 90 gün soft-sunset; hash kayıtları `trust_ttl_secs`
    // (default 7 gün). `trusted_at_epoch == 0` v0.5 upgrade'leri korunur.
    let pruned = state::get().settings.write().prune_expired();
    if pruned > 0 {
        tracing::info!("süresi dolmuş trust kaydı temizlendi: {}", pruned);
    }

    // Tokio runtime ve async thread: kritik init. Runtime build başarısız
    // olursa protokol işleyemez — fatal dialog + exit. Thread spawn hatası
    // aynı sınıfta (çekirdek işçi thread yok → HekaDrop boş pencereden ibaret
    // kalır), onu da fatal göster.
    let spawn_result = std::thread::Builder::new()
        .name("hekadrop-async".into())
        .spawn(|| {
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    ui::fatal_error_dialog(
                        "HekaDrop başlatılamıyor",
                        &format!("tokio runtime kurulamadı: {}", e),
                    );
                    std::process::exit(1);
                }
            };
            let _ = RUNTIME.set(rt.handle().clone());
            if let Err(e) = rt.block_on(async_main()) {
                tracing::error!("async_main hata: {:?}", e);
                std::process::exit(1);
            }
        });
    if let Err(e) = spawn_result {
        ui::fatal_error_dialog(
            "HekaDrop başlatılamıyor",
            &format!("async thread başlatılamadı: {}", e),
        );
        std::process::exit(1);
    }

    run_app();
}

/// Hem stdout'a hem de platforma uygun log dizinindeki `hekadrop.log` dosyasına yazar
/// (macOS: `~/Library/Logs/HekaDrop`, Linux: `~/.local/state/HekaDrop/logs`).
///
/// Log şişmesi koruması:
///   - Günlük rotation (her gün yeni dosya)
///   - Maksimum 3 gün tutulur (`max_log_files(3)`)
///   - Başlangıçta 10 MB'ı aşan günlük dosya truncate edilir
///   - Eski (>3 gün) dosyalar mekanik olarak silinir
///
/// `log_level` Settings'ten gelir (H#4 privacy control). `RUST_LOG` env var
/// set ise o öncelikli — geliştirici kaçış vanası; aksi halde verilen
/// LogLevel `hekadrop=<seviye>` direktifine dönüşür.
fn setup_logging(log_level: settings::LogLevel) {
    use tracing_appender::rolling::{RollingFileAppender, Rotation};
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(log_level.filter_directive()));

    let log_dir = platform::logs_dir();
    let _ = std::fs::create_dir_all(&log_dir);

    // Başlangıç temizliği — appender açılmadan önce diski kontrol altına al.
    truncate_oversized_logs(&log_dir, 10 * 1024 * 1024);
    cleanup_old_logs(&log_dir, 3);

    // File appender opsiyonel — disk doluysa / permission yoksa build hata
    // döner; bu durumda stdout-only mode ile devam et (degraded). Kullanıcı
    // uygulamayı başlatabilir, log dosyası yok ama core işlev çalışır.
    let file_layer = match RollingFileAppender::builder()
        .rotation(Rotation::DAILY)
        .filename_prefix("hekadrop")
        .filename_suffix("log")
        .max_log_files(3)
        .build(&log_dir)
    {
        Ok(appender) => {
            let (file_writer, guard) = tracing_appender::non_blocking(appender);
            Box::leak(Box::new(guard));
            Some(fmt::layer().with_writer(file_writer).with_ansi(false))
        }
        Err(e) => {
            // Tracing subscriber henüz kurulmadı — eprintln! tek başvuru.
            #[allow(clippy::print_stderr)]
            {
                eprintln!(
                    "[HekaDrop] log appender kurulamadı ({}); stdout-only devam",
                    e
                );
            }
            None
        }
    };

    let stdout_layer = fmt::layer().with_writer(std::io::stdout);

    tracing_subscriber::registry()
        .with(filter)
        .with(stdout_layer)
        .with(file_layer)
        .init();
}

fn cleanup_old_logs(dir: &std::path::Path, keep_days: u64) {
    let threshold =
        std::time::SystemTime::now().checked_sub(Duration::from_secs(keep_days * 86400));
    let Some(threshold) = threshold else { return };
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            if let Ok(meta) = entry.metadata() {
                if let Ok(modified) = meta.modified() {
                    if modified < threshold {
                        let _ = std::fs::remove_file(entry.path());
                    }
                }
            }
        }
    }
}

/// Herhangi bir günlük dosyası anormal şişmişse (debug seviyesinde çok çağrı olabilir)
/// startup'ta sıfırlar. Normal kullanımda bu koşul neredeyse hiç tetiklenmez.
fn truncate_oversized_logs(dir: &std::path::Path, max_bytes: u64) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            if let Ok(meta) = entry.metadata() {
                if meta.is_file() && meta.len() > max_bytes {
                    let _ = std::fs::File::create(entry.path());
                }
            }
        }
    }
}

fn run_app() -> ! {
    #[cfg(target_os = "macos")]
    let mut event_loop = EventLoopBuilder::new().build();
    #[cfg(not(target_os = "macos"))]
    let event_loop = EventLoopBuilder::new().build();

    // Dock'ta görünme — her zaman sadece menü çubuğunda (macOS'a özgü davranış;
    // Linux'ta pencere yöneticileri bunu uygulama tarafından yönetmez).
    #[cfg(target_os = "macos")]
    event_loop.set_activation_policy(ActivationPolicy::Accessory);

    let device_name = state::get().settings.read().resolved_device_name();
    let auto_accept_initial = state::get().settings.read().auto_accept;

    // Menü (tray)
    let tray_menu = Menu::new();
    let title_item = MenuItem::new(i18n::tf("tray.title_format", &[&device_name]), false, None);
    let status_item = MenuItem::new(i18n::t("tray.status.ready"), false, None);
    let show_window_item = MenuItem::new(i18n::t("tray.show_window"), true, None);
    let send_item = MenuItem::new(i18n::t("tray.send_file"), true, None);
    let cancel_item = MenuItem::new(i18n::t("tray.cancel"), false, None);
    let auto_accept_item =
        CheckMenuItem::new(i18n::t("tray.auto_accept"), true, auto_accept_initial, None);
    let history_item = MenuItem::new(i18n::t("tray.history"), true, None);
    let open_downloads = MenuItem::new(i18n::t("tray.open_downloads"), true, None);
    let open_config = MenuItem::new(i18n::t("tray.open_config"), true, None);
    let login_item = MenuItem::new(i18n::t("tray.login_item"), true, None);
    let about_item = MenuItem::new(i18n::t("tray.about"), true, None);
    let quit_item = MenuItem::new(i18n::t("tray.quit"), true, None);

    tray_menu.append(&title_item).ok();
    tray_menu.append(&status_item).ok();
    tray_menu.append(&PredefinedMenuItem::separator()).ok();
    tray_menu.append(&show_window_item).ok();
    tray_menu.append(&send_item).ok();
    tray_menu.append(&cancel_item).ok();
    tray_menu.append(&PredefinedMenuItem::separator()).ok();
    tray_menu.append(&auto_accept_item).ok();
    tray_menu.append(&history_item).ok();
    tray_menu.append(&open_downloads).ok();
    tray_menu.append(&open_config).ok();
    tray_menu.append(&login_item).ok();
    tray_menu.append(&PredefinedMenuItem::separator()).ok();
    tray_menu.append(&about_item).ok();
    tray_menu.append(&PredefinedMenuItem::separator()).ok();
    tray_menu.append(&quit_item).ok();

    // macOS/Windows'ta sol tık = pencere aç (Quick Share UX pattern), sağ tık =
    // menü. Linux AppIndicator click event yaymadığı için default'ta kalır
    // (sol tık da menüyü açar, tek yol).
    let tray_builder = TrayIconBuilder::new()
        .with_menu(Box::new(tray_menu))
        .with_title("⇄")
        .with_tooltip("HekaDrop");
    #[cfg(not(target_os = "linux"))]
    let tray_builder = tray_builder.with_menu_on_left_click(false);
    // Tray kritik değil — Linux'ta AppIndicator yoksa, Windows'ta bazı session
    // config'lerinde build fail edebilir. Tray olmadan ana pencere + IPC
    // çalışmaya devam eder; kullanıcı tray özelliklerini kaybeder ama
    // protokol ve dosya aktarımı etkilenmez (degraded mode).
    let tray = match tray_builder.build() {
        Ok(t) => Some(t),
        Err(e) => {
            tracing::error!("tray icon oluşturulamadı ({}); tray'siz devam", e);
            None
        }
    };

    // Ana pencere + WebView — KRİTİK. Bunlar olmadan UI yok, fatal.
    let window = match WindowBuilder::new()
        .with_title("HekaDrop")
        .with_inner_size(tao::dpi::LogicalSize::new(340.0, 460.0))
        .with_min_inner_size(tao::dpi::LogicalSize::new(320.0, 400.0))
        .with_resizable(false)
        .with_visible(true)
        .build(&event_loop)
    {
        Ok(w) => w,
        Err(e) => {
            ui::fatal_error_dialog(
                "HekaDrop başlatılamıyor",
                &format!("pencere oluşturulamadı: {}", e),
            );
            // Fatal startup; ?-propagation main()'e tanrı-Result zorlar — exit
            // burada anlamlı: kullanıcı hata gördü, RAII temizliğe gerek yok.
            #[allow(clippy::exit)]
            std::process::exit(1);
        }
    };

    let builder = WebViewBuilder::new()
        .with_html(WINDOW_HTML)
        .with_ipc_handler(|req| {
            let cmd = req.into_body();
            handle_ipc(&cmd);
        })
        .with_drag_drop_handler(|event| {
            if let DragDropEvent::Drop { paths, .. } = event {
                if !paths.is_empty() {
                    // Klasör bırakıldıysa recursive olarak içindeki tüm
                    // dosyaları düzleştir (flatten). Symlink'leri takip ETMEZ
                    // (döngü koruması).
                    let files = expand_folder_drops(paths);
                    if files.is_empty() {
                        info!("[ui] drop: içerik yok");
                    } else {
                        info!("[ui] drop: {} dosya", files.len());
                        if let Some(rt) = RUNTIME.get() {
                            rt.spawn(initiate_send_flow_with(files));
                        }
                    }
                }
            }
            true
        });

    // Linux (GTK): wry WebView bir gtk::Container içine monte edilmelidir;
    // raw-window-handle yolu desteklenmez. macOS/Windows'ta `.build(&window)`.
    // WebView kritik — UI'ın tamamı bunun içinde. Hata → fatal + exit.
    #[cfg(target_os = "linux")]
    let webview = {
        use tao::platform::unix::WindowExtUnix;
        use wry::WebViewBuilderExtUnix;
        let Some(vbox) = window.default_vbox() else {
            ui::fatal_error_dialog(
                "HekaDrop başlatılamıyor",
                "GTK pencere kabı (vbox) alınamadı. GTK3 + WebKit2GTK kurulu olduğundan emin olun.",
            );
            // Fatal startup; bkz. yukarı.
            #[allow(clippy::exit)]
            std::process::exit(1);
        };
        match builder.build_gtk(vbox) {
            Ok(w) => w,
            Err(e) => {
                ui::fatal_error_dialog(
                    "HekaDrop başlatılamıyor",
                    &format!("webview oluşturulamadı: {}", e),
                );
                // Fatal startup; bkz. yukarı.
                #[allow(clippy::exit)]
                std::process::exit(1);
            }
        }
    };
    #[cfg(not(target_os = "linux"))]
    let webview = match builder.build(&window) {
        Ok(w) => w,
        Err(e) => {
            ui::fatal_error_dialog(
                "HekaDrop başlatılamıyor",
                &format!("webview oluşturulamadı: {}", e),
            );
            // Fatal startup; bkz. yukarı.
            #[allow(clippy::exit)]
            std::process::exit(1);
        }
    };

    // İlk açılışta i18n sözlüğünü hazır tut — HTML `settings_get` IPC'si de
    // push_i18n_to_ui'yi çağırır; fakat `settings_get` gelmeden (race) bazı
    // platformlarda webview `applyI18n` çağrısını kaçırabilir. Kuyruğa ekleyerek
    // event loop ilk tick'te script'i çalıştırır.
    push_i18n_to_ui();
    maybe_push_onboarding();

    let menu_channel = MenuEvent::receiver();
    #[cfg(not(target_os = "linux"))]
    let tray_channel = TrayIconEvent::receiver();
    let open_downloads_id = open_downloads.id().clone();
    let open_config_id = open_config.id().clone();
    let about_item_id = about_item.id().clone();
    let quit_item_id = quit_item.id().clone();
    let auto_accept_id = auto_accept_item.id().clone();
    let login_item_id = login_item.id().clone();
    let history_item_id = history_item.id().clone();
    let send_item_id = send_item.id().clone();
    let cancel_item_id = cancel_item.id().clone();
    let show_window_item_id = show_window_item.id().clone();

    let mut last_status_text = String::new();
    let mut last_ui_progress_signature = String::new();

    event_loop.run(move |event, _target, control_flow| {
        *control_flow =
            ControlFlow::WaitUntil(std::time::Instant::now() + Duration::from_millis(250));

        // Pencere olayları
        if let Event::WindowEvent {
            event: WindowEvent::CloseRequested,
            ..
        } = &event
        {
            // Kapatma yerine gizle — uygulama arkaplanda çalışmaya devam eder.
            window.set_visible(false);
            ui::notify(i18n::t("notify.app_name"), i18n::t("notify.background"));
            return;
        }

        // IPC'den gelen pencere istekleri
        if state::consume_hide_window() {
            window.set_visible(false);
        }
        if state::consume_show_window() {
            window.set_visible(true);
            window.set_focus();
        }

        // IPC'den gelen JS kuyruğunu boşalt
        for js in state::drain_js() {
            let _ = webview.evaluate_script(&js);
        }

        // Canlı durum
        let progress = state::read_progress();
        let active = matches!(progress, state::ProgressState::Receiving { .. });
        cancel_item.set_enabled(active);
        let status_text = progress_label(&progress);
        if status_text != last_status_text {
            status_item.set_text(&status_text);
            if let Some(ref t) = tray {
                let _ = t.set_tooltip(Some(i18n::tf("tray.tooltip_format", &[&status_text])));
            }
            last_status_text = status_text.clone();
        }

        // Pencere progress + status push (değişiklik varsa)
        let sig = progress_signature(&progress);
        if sig != last_ui_progress_signature {
            push_progress_to_ui(&webview, &progress);
            let js_status = format!(
                "window.updateStatus && window.updateStatus({})",
                js_string(&status_text)
            );
            let _ = webview.evaluate_script(&js_status);
            last_ui_progress_signature = sig;
        }

        // Tray ikonunun kendisine tıklama (macOS/Windows): sol tık → pencere aç.
        // Sağ tık menüyü tray-icon tarafından otomatik açılır.
        // Doğrudan `window.set_visible/set_focus` kullanıyoruz; state flag
        // üzerinden gitseydik `consume_show_window()` bu tick'te geçildiği için
        // pencere bir sonraki tick'e (≤250ms) kalırdı.
        #[cfg(not(target_os = "linux"))]
        while let Ok(ev) = tray_channel.try_recv() {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = ev
            {
                window.set_visible(true);
                window.set_focus();
            }
        }

        // Tray menü olayları
        while let Ok(ev) = menu_channel.try_recv() {
            if ev.id == quit_item_id {
                info!("kullanıcı çıkışı seçti (tray)");
                graceful_quit();
            } else if ev.id == show_window_item_id {
                state::request_show_window();
            } else if ev.id == send_item_id {
                if let Some(rt) = RUNTIME.get() {
                    rt.spawn(initiate_send_flow());
                }
            } else if ev.id == cancel_item_id {
                state::request_cancel_all();
                ui::notify(
                    i18n::t("notify.app_name"),
                    i18n::t("notify.cancel_requested"),
                );
            } else if ev.id == open_downloads_id {
                open_downloads_folder();
            } else if ev.id == open_config_id {
                open_config_file();
            } else if ev.id == auto_accept_id {
                // Tray ve Settings panelini tek kod yolundan geçir: tray
                // değişikliğini de `handle_settings_save` merkezine yollarız
                // böylece WebView push + tek atomic-write (save_debounced)
                // davranışı her iki kaynak için aynı olur.
                let new_val = auto_accept_item.is_checked();
                let current = state::get().settings.read().clone();
                let payload = serde_json::json!({
                    "device_name": current.device_name,
                    "download_dir": current.download_dir.as_ref().map(|p| p.to_string_lossy()),
                    "auto_accept": new_val,
                    "advertise": current.advertise,
                    "log_level": current.log_level.as_str(),
                    "keep_stats": current.keep_stats,
                    "disable_update_check": current.disable_update_check,
                });
                handle_settings_save(&payload.to_string());
                // WebView Settings sekmesi açıksa tray değişikliğini yansıt —
                // `handle_settings_save` push etmez; applySettings burada tetiklenir.
                push_settings_to_ui();
                info!("auto_accept → {} (tray)", new_val);
                ui::notify(
                    i18n::t("notify.app_name"),
                    if new_val {
                        i18n::t("notify.auto_accept_on")
                    } else {
                        i18n::t("notify.auto_accept_off")
                    },
                );
            } else if ev.id == login_item_id {
                toggle_login_item();
            } else if ev.id == history_item_id {
                show_history();
            } else if ev.id == about_item_id {
                ui::notify(i18n::t("notify.app_name"), i18n::t("notify.about"));
            }
        }
    });
}

fn handle_ipc(cmd: &str) {
    // PRIVACY: Metin gönderim komutları kullanıcı verisi içerir; log'a düşmesin.
    // `send_text::` prefix'i yalnız başlangıç kısmıyla logla, geri kalanı redact.
    // PERF: IPC handler UI/event-loop thread'inde çalışır; `len()` O(1) bayt
    // sayısı yeter — `chars().count()` büyük metinlerde O(n) gecikme yaratır.
    if let Some(rest) = cmd.strip_prefix("send_text::") {
        info!("[ui] ipc: send_text:: ({} bayt)", rest.len());
        if let Some(rt) = RUNTIME.get() {
            let text = rest.to_string();
            rt.spawn(initiate_text_send_flow(text));
        }
        return;
    }
    info!("[ui] ipc: {}", cmd);
    if let Some(rest) = cmd.strip_prefix("settings_save::") {
        handle_settings_save(rest);
        return;
    }
    if let Some(path) = cmd.strip_prefix("reveal::") {
        reveal_in_finder(path);
        return;
    }
    if let Some(name) = cmd.strip_prefix("trust_remove::") {
        let st = state::get();
        let snap = {
            let mut s = st.settings.write();
            s.remove_trusted(name);
            s.clone()
        };
        let _ = snap.save();
        push_trusted_to_ui();
        ui::notify(
            i18n::t("notify.app_name"),
            &i18n::tf("notify.trust_removed", &[name]),
        );
        return;
    }
    match cmd {
        "send" => {
            if let Some(rt) = RUNTIME.get() {
                rt.spawn(initiate_send_flow());
            }
        }
        "paste_send" => {
            // Ctrl/Cmd+V global handler — pano okuması Linux/macOS'ta external
            // command spawn içerir (xclip/pbpaste), Windows'ta OpenClipboard
            // bir komşu uygulamayı bekleyebilir. Her ikisi de IPC thread'ini
            // bloklar; `spawn_blocking` ile arkaplana al.
            if let Some(rt) = RUNTIME.get() {
                let rt_handle = rt.clone();
                rt.spawn(async move {
                    let clipboard = tokio::task::spawn_blocking(platform::paste_from_clipboard)
                        .await
                        .ok()
                        .flatten();
                    match clipboard {
                        Some(t) if !t.trim().is_empty() => {
                            rt_handle.spawn(initiate_text_send_flow(t));
                        }
                        _ => {
                            ui::notify(i18n::t("notify.app_name"), i18n::t("notify.text_empty"));
                        }
                    }
                });
            }
        }
        "settings_get" => {
            // i18n'i de push et — dil runtime'da değişmez (Lang OnceLock) ama
            // boot race'inde settings_get script başlamadan gelirse applyI18n
            // henüz tanımlı değildir; burada geri-yüklüyoruz.
            push_i18n_to_ui();
            push_settings_to_ui();
            push_trusted_to_ui();
        }
        "i18n_refresh" => push_i18n_to_ui(),
        "trusted_refresh" => push_trusted_to_ui(),
        "stats_refresh" => push_stats_to_ui(),
        "stats_reset" => {
            let st = state::get();
            let snap = {
                let mut s = st.stats.write();
                *s = stats::Stats::default();
                s.clone()
            };
            let _ = snap.save();
            push_stats_to_ui();
            ui::notify(i18n::t("notify.app_name"), i18n::t("notify.stats_reset"));
        }
        "open_logs" => {
            platform::open_path(&platform::logs_dir());
        }
        "check_update" => {
            if let Some(rt) = RUNTIME.get() {
                rt.spawn(check_update_async());
            }
        }
        "trusted_clear" => {
            let st = state::get();
            let snap = {
                let mut s = st.settings.write();
                s.trusted_devices.clear();
                s.clone()
            };
            let _ = snap.save();
            push_trusted_to_ui();
            ui::notify(i18n::t("notify.app_name"), i18n::t("notify.trust_cleared"));
        }
        "history_refresh" => push_history_to_ui(),
        "onboarding_done" => {
            // İlk açılış modal'ı dismiss edildi — flag'i set edip hemen diske
            // yaz (debounce YOK; kullanıcı restart ederse modal tekrar
            // açılmasın, kritik persistency noktası).
            let st = state::get();
            let snap = {
                let mut s = st.settings.write();
                if s.first_launch_completed {
                    return;
                }
                s.first_launch_completed = true;
                s.clone()
            };
            if let Err(e) = snap.save() {
                tracing::warn!("onboarding_done save: {}", e);
            }
            info!("[ui] onboarding tamamlandı");
        }
        "pick_downloads" => {
            if let Some(rt) = RUNTIME.get() {
                rt.spawn(async {
                    if let Some(path) = ui::choose_folder().await {
                        let path_str = path.to_string_lossy().to_string();
                        state::enqueue_js(format!(
                            "document.getElementById('set-downloads').value = {}",
                            js_string(&path_str)
                        ));
                    }
                });
            }
        }
        "downloads" => open_downloads_folder(),
        "config" => open_config_file(),
        "hide" => {
            state::request_hide_window();
            ui::notify(i18n::t("notify.app_name"), i18n::t("notify.hidden"));
        }
        "quit" => {
            info!("kullanıcı çıkışı seçti (in-app)");
            graceful_quit();
        }
        other => tracing::warn!("bilinmeyen ipc: {}", other),
    }
}

/// Uygulamayı düzgün sonlandır — platform-spesifik "auto-restart" politikalarını
/// çiğnemeden.
///
/// **Kritik:** launchd plist'i `KeepAlive=true` ile kurulu. Düz `std::process::exit`
/// launchd tarafından "crash" gibi algılanır ve `ThrottleInterval` (10 sn) sonrası
/// otomatik restart atılır — kullanıcı "Çıkış" dediğinde uygulama dönüyor gibi
/// görünür. Çözüm: önce launchd agent'ını `unload` et (sadece mevcut oturum;
/// plist dosyasını **silmeyiz**, bir sonraki login'de yine yüklenir), sonra
/// process'i sonlandır.
///
/// Linux'ta systemd user unit aynı amaçla durdurulur (Restart= direktifi varsa
/// tekrar başlatmasın diye). Windows'ta autostart HKCU Run key'i pasif —
/// exit yeterli.
fn graceful_quit() -> ! {
    #[cfg(target_os = "macos")]
    {
        if let Ok(home) = std::env::var("HOME") {
            let plist_path = format!("{}/Library/LaunchAgents/com.sourvice.hekadrop.plist", home);
            if std::path::Path::new(&plist_path).exists() {
                info!("launchd agent unload: {}", plist_path);
                let _ = std::process::Command::new("launchctl")
                    .args(["unload", &plist_path])
                    .status();
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        // Unit yoksa `stop` hata döner — sessiz yoksay.
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "stop", "hekadrop.service"])
            .status();
    }
    // Quit handler — daemon'ları durdurduktan sonra event loop'u beklemeden
    // çık. Wry'de event-loop kontrol akışı dışına temiz çıkış yolu yok.
    #[allow(clippy::exit)]
    std::process::exit(0);
}

fn handle_settings_save(json: &str) {
    // H#4: JSON payload'ına 4 yeni privacy alanı eklendi. Privacy alanları
    // Option ile tanımlı — UI eski sürümse ya da alanı göndermezse mevcut
    // değer korunur (partial update); None → no-op, Some(v) → yaz.
    // `auto_accept` geriye dönük uyumluluk için zorunlu `bool` kalmıştır.
    // `log_level` UI'dan serbest string olarak gelir, `parse_or_default`
    // ile güvenli parse edilir (bilinmeyen input Info'ya düşer, reject yok).
    #[derive(serde::Deserialize, Debug)]
    struct Incoming {
        device_name: Option<String>,
        download_dir: Option<String>,
        auto_accept: bool,
        #[serde(default)]
        advertise: Option<bool>,
        #[serde(default)]
        log_level: Option<String>,
        #[serde(default)]
        keep_stats: Option<bool>,
        #[serde(default)]
        disable_update_check: Option<bool>,
    }
    let parsed: Incoming = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("settings_save parse: {}", e);
            return;
        }
    };
    {
        let st = state::get();
        let snap = {
            let mut s = st.settings.write();
            s.device_name = parsed.device_name.filter(|x| !x.is_empty());
            s.download_dir = parsed.download_dir.map(std::path::PathBuf::from);
            s.auto_accept = parsed.auto_accept;
            if let Some(v) = parsed.advertise {
                s.advertise = v;
            }
            if let Some(ref raw) = parsed.log_level {
                s.log_level = settings::LogLevel::parse_or_default(raw);
            }
            if let Some(v) = parsed.keep_stats {
                s.keep_stats = v;
            }
            if let Some(v) = parsed.disable_update_check {
                s.disable_update_check = v;
            }
            s.clone()
        };
        // Pre-flight sync validation: save_debounced 100 ms sonra arka planda
        // yazar, oradaki hata kullanıcıya ulaşmaz — burada eşzamanlı doğrulayıp
        // erken çıkıyoruz ki geçersiz bir `download_dir` UI'da sessizce
        // "kaydedildi" gibi görünmesin. None ise resolved default kullanılır;
        // o path'i `default_download_dir()` platform garantisiyle üretir,
        // doğrulamaya gerek yok.
        if let Some(ref dir) = snap.download_dir {
            if let Err(e) = settings::validate_download_dir(dir) {
                tracing::warn!("[ui] download_dir geçersiz: {}", e);
                ui::notify(
                    i18n::t("notify.app_name"),
                    &format!("download_dir geçersiz: {}", e),
                );
                return;
            }
        }
        // RUNTIME handle tokio async thread init'inde set edilir (main.rs:170).
        // `handle_settings_save` UI event-loop thread'inden çağrılıyor → burada
        // `Handle::try_current()` çalışmaz. OnceLock henüz set edilmemişse
        // (teorik: async init daha başlamadıysa) sync fallback ile yaz.
        match RUNTIME.get() {
            Some(h) => snap.save_debounced(h),
            None => {
                if let Err(e) = snap.save() {
                    tracing::warn!("settings save fallback (no runtime): {}", e);
                }
            }
        }
    }
    info!("[ui] ayarlar güncellendi");
    state::enqueue_js("window.showSaved && window.showSaved()".into());
    ui::notify(i18n::t("notify.app_name"), i18n::t("notify.settings_saved"));
}

/// Webview'a i18n key→translation sözlüğünü enjekte eder. Rust tarafındaki
/// `Lang::Tr`/`Lang::En` seçimi tüm çevirileri `t()` üzerinden çözer; JS
/// `window.__I18N__` üzerinden okur, `applyI18n()` DOM'a uygular.
///
/// Settings panel dilini değiştirmek UI restart istemesin diye `settings_get`
/// IPC'sinde de çağrılır (çevirinin kendisi sabit, ama boot sırası garantili olmayabilir).
fn push_i18n_to_ui() {
    // Tüm webview.* + time.* + ortak key'ler. Webview'ın ihtiyacı olan tüm
    // i18n key'lerini burada enumerate ediyoruz — JS tarafında `t(key)` çağrısı
    // buradaki map'e hit etmeli, aksi halde `?key?` fallback gözükür.
    let keys: &[&str] = &[
        "webview.status.ready",
        "webview.tab.home",
        "webview.tab.history",
        "webview.tab.settings",
        "webview.tab.diag",
        "webview.drop.line1",
        "webview.drop.line2",
        "webview.progress.preparing",
        "webview.progress.default",
        "webview.text.placeholder",
        "webview.text.send",
        "webview.btn.open_downloads",
        "webview.btn.hide_to_tray",
        "webview.btn.quit",
        "webview.history.empty",
        "webview.btn.refresh",
        "webview.settings.device_label",
        "webview.settings.device_placeholder",
        "webview.settings.downloads_label",
        "webview.settings.change",
        "webview.settings.auto_accept",
        "webview.settings.auto_accept_hint",
        "webview.settings.trusted_label",
        "webview.settings.trusted_hint",
        "webview.settings.trusted_empty",
        "webview.settings.clear_all",
        "webview.settings.save",
        "webview.settings.saved",
        "webview.settings.trust_remove",
        "webview.settings.trust_ttl_days",
        "webview.settings.trust_clear_title",
        "webview.settings.trust_clear_body",
        "webview.settings.trust_clear_cancel",
        "webview.settings.trust_clear_confirm",
        "webview.trusted.ttl_label",
        "webview.trusted.ttl_expired",
        "webview.trusted.expired_tooltip",
        // H#4 privacy section
        "webview.privacy.title",
        "webview.privacy.advertise.label",
        "webview.privacy.advertise.desc",
        "webview.privacy.log_level.label",
        "webview.privacy.log_level.desc",
        "webview.privacy.log_level.error",
        "webview.privacy.log_level.warn",
        "webview.privacy.log_level.info",
        "webview.privacy.log_level.debug",
        "webview.privacy.keep_stats.label",
        "webview.privacy.keep_stats.desc",
        "webview.privacy.update_check.label",
        "webview.privacy.update_check.desc",
        "webview.privacy.restart_notice",
        "webview.privacy.restart_badge",
        "webview.privacy.hotswap_badge",
        "webview.badge.on",
        "webview.badge.off",
        "webview.diag.section.app",
        "webview.diag.version",
        "webview.diag.device",
        "webview.diag.mdns",
        "webview.diag.port",
        "webview.diag.section.stats",
        "webview.diag.first_use",
        "webview.diag.last_use",
        "webview.diag.received",
        "webview.diag.sent",
        "webview.diag.top_rx",
        "webview.diag.top_tx",
        "webview.diag.check_update",
        "webview.diag.open_logs",
        "webview.diag.reset_stats",
        "webview.diag.reset_confirm",
        "webview.diag.files_suffix",
        "webview.footer",
    ];
    let map: serde_json::Map<String, serde_json::Value> = keys
        .iter()
        .map(|k| {
            (
                (*k).to_string(),
                serde_json::Value::String(i18n::t(k).to_string()),
            )
        })
        .collect();
    let payload = serde_json::Value::Object(map);
    // `enqueue_js` Vec<String> kuyruğa alır; çoklu eval güvenli. `applyI18n`
    // fonksiyonu script block içinde tanımlı — bu push ondan sonra geldiğinde
    // doğrudan çağrılır; öncesinde geldiyse window.__I18N__ setlenir, script
    // tag'i load olunca boot path'i yakalar.
    let js = format!(
        "window.__I18N__ = {}; window.applyI18n && window.applyI18n();",
        payload
    );
    state::enqueue_js(js);
}

/// İlk açılışta (veya upgrade eden kullanıcının ilk sürüm sonrasında) WebView
/// yüklenir yüklenmez onboarding modal'ını gösterir. `first_launch_completed`
/// zaten true ise no-op. `act('onboarding_done')` IPC'si flag'i true'ya çekip
/// diske yazar → bir sonraki boot'ta modal tekrar gelmez.
fn maybe_push_onboarding() {
    let (should_show, device_name) = {
        let st = state::get();
        let s = st.settings.read();
        (!s.first_launch_completed, s.resolved_device_name())
    };
    if !should_show {
        return;
    }
    let title = i18n::t("onboarding.title");
    let body = i18n::tf("onboarding.body", &[&device_name]);
    let cta_settings = i18n::t("onboarding.cta_settings");
    let cta_dismiss = i18n::t("onboarding.cta_dismiss");
    // JSON.stringify-safe: `serde_json::json!` string'leri kendi escape eder,
    // satır içi concat yapmak yerine bütün payload'u tek bir JSON literal
    // olarak pass ederiz → JS tarafında window.showOnboarding(cfg).
    let js = format!(
        "window.showOnboarding && window.showOnboarding({})",
        serde_json::json!({
            "title": title,
            "body": body,
            "cta_settings": cta_settings,
            "cta_dismiss": cta_dismiss,
        })
    );
    state::enqueue_js(js);
}

fn push_settings_to_ui() {
    let st = state::get();
    let s = st.settings.read();
    let resolved_name = s.resolved_device_name();
    let resolved_dl = s.resolved_download_dir().to_string_lossy().to_string();
    // H#4: 4 yeni privacy alanı JS'ye push edilir; UI Settings sekmesinde
    // checkbox/select olarak render. `log_level` lowercase string, option
    // karşılaştırması JS tarafında direkt bu değerle yapılır.
    let payload = serde_json::json!({
        "device_name": s.device_name.clone().unwrap_or(resolved_name),
        "download_dir": s.download_dir.as_ref().map(|p| p.to_string_lossy().to_string()).unwrap_or(resolved_dl),
        "auto_accept": s.auto_accept,
        "advertise": s.advertise,
        "log_level": s.log_level.as_str(),
        "keep_stats": s.keep_stats,
        "disable_update_check": s.disable_update_check,
    });
    drop(s);
    let js = format!("window.applySettings && window.applySettings({})", payload);
    state::enqueue_js(js);
}

fn push_stats_to_ui() {
    let st = state::get();
    let s = st.stats.read().clone();
    drop(st);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let first_use_human = if s.first_use_epoch > 0 {
        relative_time(now.saturating_sub(s.first_use_epoch))
    } else {
        i18n::t("time.none").to_string()
    };
    let last_use_human = if s.last_use_epoch > 0 {
        relative_time(now.saturating_sub(s.last_use_epoch))
    } else {
        i18n::t("time.none").to_string()
    };

    let top_rx = s
        .top_rx_device()
        .map(|(n, b)| format!("{} ({})", n, human_size(b as i64)))
        .unwrap_or_else(|| "—".to_string());
    let top_tx = s
        .top_tx_device()
        .map(|(n, b)| format!("{} ({})", n, human_size(b as i64)))
        .unwrap_or_else(|| "—".to_string());

    let payload = serde_json::json!({
        "app_version": env!("CARGO_PKG_VERSION"),
        "device_name": st_settings_resolved_name(),
        "service_type": crate::config::service_type(),
        "port": state::listen_port(),
        "log_dir": platform::logs_dir().to_string_lossy(),
        "config_path": settings::config_path().to_string_lossy(),
        "bytes_received": human_size(s.bytes_received as i64),
        "bytes_sent": human_size(s.bytes_sent as i64),
        "files_received": s.files_received,
        "files_sent": s.files_sent,
        "first_use": first_use_human,
        "last_use": last_use_human,
        "top_rx": top_rx,
        "top_tx": top_tx,
    });
    state::enqueue_js(format!(
        "window.applyStats && window.applyStats({})",
        payload
    ));
}

fn st_settings_resolved_name() -> String {
    state::get().settings.read().resolved_device_name()
}

fn push_trusted_to_ui() {
    let st = state::get();
    // Issue #17: `applyTrusted` JS artık zengin nesne dizisi kabul eder —
    // her kayıt `{name, display, trusted_at_epoch, ttl_secs, has_hash}`
    // yapısında; UI TTL rozetini ve "süresi doldu" uyarısını burada hesaplar.
    //
    // `name` ayrı alan olarak gönderilir (review #34 LOW): UI `trust_remove`
    // IPC çağrısında `display` yerine raw `name` kullanır, böylece
    // "Pixel 7 (abcdef01)" gibi display string'leri kayıt adıyla
    // eşleşmediği için silme sessizce başarısız olmaz. Backward-compat için
    // `display` alanı korunur (zengin başlık metni).
    let s = st.settings.read();
    let ttl_secs = s.trust_ttl_secs;
    let items: Vec<serde_json::Value> = s
        .trusted_devices
        .iter()
        .map(|d| {
            serde_json::json!({
                "name": d.name,
                "display": d.display(),
                "trusted_at_epoch": d.trusted_at_epoch,
                "ttl_secs": ttl_secs,
                "has_hash": d.secret_id_hash.is_some(),
            })
        })
        .collect();
    drop(s);
    let payload = serde_json::Value::Array(items);
    let js = format!("window.applyTrusted && window.applyTrusted({})", payload);
    state::enqueue_js(js);
}

fn push_history_to_ui() {
    let items = state::read_history();
    let now = std::time::SystemTime::now();
    let json_items: Vec<serde_json::Value> = items
        .iter()
        .map(|h| {
            let age = now
                .duration_since(h.when)
                .map(|d| relative_time(d.as_secs()))
                .unwrap_or_else(|_| "az önce".into());
            serde_json::json!({
                "file_name": h.file_name,
                "path": h.path.to_string_lossy(),
                "size_human": human_size(h.size),
                "device": h.device,
                "age": age,
                "sha256": h.sha256_short,
            })
        })
        .collect();
    let js = format!(
        "window.applyHistory && window.applyHistory({})",
        serde_json::Value::Array(json_items)
    );
    state::enqueue_js(js);
}

fn reveal_in_finder(path: &str) {
    platform::reveal_path(std::path::Path::new(path));
}

fn open_downloads_folder() {
    let dl = state::get().settings.read().resolved_download_dir();
    platform::open_path(&dl);
}

fn open_config_file() {
    let path = settings::config_path();
    if !path.exists() {
        // Snapshot clone + drop guard → disk I/O lock dışında. Yavaş FS'te
        // (encrypted home, FUSE) read() guard tüm write()'ları bloklardı.
        let snap = state::get().settings.read().clone();
        let _ = snap.save();
    }
    platform::reveal_path(&path);
}

fn progress_signature(p: &state::ProgressState) -> String {
    match p {
        state::ProgressState::Idle => "idle".into(),
        state::ProgressState::Receiving {
            device,
            file,
            percent,
        } => format!("recv:{}:{}:{}", device, file, percent),
        state::ProgressState::Completed { file } => format!("done:{}", file),
    }
}

fn js_string(s: &str) -> String {
    let escaped = s
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n");
    format!("\"{}\"", escaped)
}

fn push_progress_to_ui(webview: &wry::WebView, p: &state::ProgressState) {
    let js = match p {
        state::ProgressState::Idle => {
            "window.updateProgress && window.updateProgress(-1, '')".to_string()
        }
        state::ProgressState::Receiving {
            device,
            file,
            percent,
        } => format!(
            "window.updateProgress && window.updateProgress({}, {})",
            percent,
            js_string(&format!("{} • {} ({}%)", device, file, percent))
        ),
        state::ProgressState::Completed { file } => format!(
            "window.updateProgress && window.updateProgress(100, {}); setTimeout(() => window.updateProgress(-1, ''), 2500)",
            js_string(&format!("✓ {}", file))
        ),
    };
    let _ = webview.evaluate_script(&js);
}

fn progress_label(p: &state::ProgressState) -> String {
    match p {
        state::ProgressState::Idle => i18n::t("tray.status.ready").to_string(),
        state::ProgressState::Receiving {
            device,
            file,
            percent,
        } => i18n::tf(
            "tray.status.receiving",
            &[device, file, &percent.to_string()],
        ),
        state::ProgressState::Completed { file } => i18n::tf("tray.status.completed", &[file]),
    }
}

async fn initiate_send_flow() {
    let Some(files) = ui::choose_files().await else {
        return;
    };
    initiate_send_flow_with(files).await;
}

async fn initiate_send_flow_with(files: Vec<std::path::PathBuf>) {
    if files.is_empty() {
        return;
    }
    info!("[send_flow] {} dosya ile başlatılıyor", files.len());

    ui::notify(i18n::t("notify.app_name"), i18n::t("notify.scanning"));

    let own_port = state::listen_port();
    let devices = match discovery::scan(Duration::from_secs(3), own_port).await {
        Ok(v) => v,
        Err(e) => {
            ui::show_info(i18n::t("send.discovery_error"), &format!("{:#}", e));
            return;
        }
    };

    if devices.is_empty() {
        ui::show_info(i18n::t("notify.app_name"), i18n::t("dialog.no_devices"));
        return;
    }

    let labels: Vec<String> = devices
        .iter()
        .map(|d| format!("{} — {} ({}:{})", d.kind_label(), d.name, d.addr, d.port))
        .collect();
    let Some(idx) = ui::choose_device(labels).await else {
        return;
    };
    let device = devices[idx].clone();

    let summary = if files.len() == 1 {
        files[0]
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("dosya")
            .to_string()
    } else {
        format!("{} dosya", files.len())
    };
    ui::notify(
        i18n::t("notify.app_name"),
        &i18n::tf("notify.sending_to", &[&device.name, &summary]),
    );

    let req = sender::SendRequest {
        device: device.clone(),
        files,
    };
    match sender::send(req).await {
        Ok(()) => {
            ui::notify(
                i18n::t("notify.app_name"),
                &i18n::tf("notify.sent_to", &[&device.name]),
            );
        }
        Err(e) => {
            tracing::warn!("send hatası: {:#}", e);
            ui::show_info(i18n::t("send.send_error"), &format!("{:#}", e));
        }
    }
}

async fn initiate_text_send_flow(text: String) {
    let text = text.trim_end_matches(['\r', '\n']).to_string();
    if text.is_empty() {
        ui::notify(i18n::t("notify.app_name"), i18n::t("notify.text_empty"));
        return;
    }
    info!(
        "[send_flow] metin gönderimi ({} karakter)",
        text.chars().count()
    );

    ui::notify(i18n::t("notify.app_name"), i18n::t("notify.scanning"));

    let own_port = state::listen_port();
    let devices = match discovery::scan(Duration::from_secs(3), own_port).await {
        Ok(v) => v,
        Err(e) => {
            ui::show_info(i18n::t("send.discovery_error"), &format!("{:#}", e));
            return;
        }
    };

    if devices.is_empty() {
        ui::show_info(i18n::t("notify.app_name"), i18n::t("dialog.no_devices"));
        return;
    }

    let labels: Vec<String> = devices
        .iter()
        .map(|d| format!("{} — {} ({}:{})", d.kind_label(), d.name, d.addr, d.port))
        .collect();
    let Some(idx) = ui::choose_device(labels).await else {
        return;
    };
    let device = devices[idx].clone();

    ui::notify(
        i18n::t("notify.app_name"),
        &i18n::tf(
            "notify.sending_to",
            &[&device.name, i18n::t("sender.text_summary")],
        ),
    );

    let req = sender::SendTextRequest {
        device: device.clone(),
        text,
    };
    match sender::send_text(req).await {
        Ok(()) => {
            ui::notify(
                i18n::t("notify.app_name"),
                &i18n::tf("notify.text_sent_to", &[&device.name]),
            );
        }
        Err(e) => {
            tracing::warn!("send_text hatası: {:#}", e);
            ui::show_info(i18n::t("send.send_error"), &format!("{:#}", e));
        }
    }
}

fn show_history() {
    let items = state::read_history();
    if items.is_empty() {
        ui::show_info(
            i18n::t("dialog.history.title"),
            i18n::t("dialog.history.empty"),
        );
        return;
    }
    let now = std::time::SystemTime::now();
    let body: String = items
        .iter()
        .enumerate()
        .map(|(i, h)| {
            let age = now
                .duration_since(h.when)
                .map(|d| relative_time(d.as_secs()))
                .unwrap_or_else(|_| "az önce".to_string());
            format!(
                "{}. {}  •  {}  •  {}  •  {}",
                i + 1,
                h.file_name,
                human_size(h.size),
                h.device,
                age
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    ui::show_info(i18n::t("dialog.history.title"), &body);
}

/// Update kontrolü sonuç kategorisi — UI'da farklı stil + metin için.
///
/// Her varyant Diagnostics tab'indeki `#update-status` div'ine ayrı `kind`
/// (CSS class) ile render edilir. HTTP failure ile rate-limit ayrımı GitHub'ın
/// `403 rate limit exceeded` cevabından kategorize edilir (curl stderr +
/// exit code yeterli ipucu veriyor; gövde parse denemesi yan etkisiz).
#[derive(Debug)]
enum UpdateCheckOutcome {
    Disabled,
    Current,
    Available { tag: String, url: String },
    NetworkError,
    RateLimited,
    ApiError(String),
}

/// UI'a update status push et. `kind` CSS class adıdır: `info` / `success` /
/// `error`. Window açık değilse JS sessizce yutulur (enqueue_js buffer'lanır,
/// sonraki eval bunu drain eder).
fn push_update_status(msg: &str, kind: &str) {
    state::enqueue_js(format!(
        "window.setUpdateStatus && window.setUpdateStatus({}, {})",
        js_string(msg),
        js_string(kind)
    ));
}

async fn check_update_async() {
    // H#4 privacy control: iki opt-out yolu OR'lanır.
    //   - `HEKADROP_NO_UPDATE_CHECK` env var (CI / dev / deterministic test)
    //   - `Settings.disable_update_check` (UI toggle; Dalga 2'den itibaren
    //     default `true` — privacy-first)
    // Her ikisi de "skip" anlamına gelir; kullanıcıya şeffaf bilgi ver.
    let env_off = std::env::var_os("HEKADROP_NO_UPDATE_CHECK").is_some();
    let setting_off = state::get().settings.read().disable_update_check;
    if env_off || setting_off {
        info!(
            "update_check skipped (env={}, setting={})",
            env_off, setting_off
        );
        render_update_outcome(UpdateCheckOutcome::Disabled);
        return;
    }

    let current = env!("CARGO_PKG_VERSION");
    // `spawn_blocking` içinde curl'ün stdout + exit status'unu birlikte
    // yakalıyoruz; network hatası vs rate-limit vs parse hatası farkını
    // burada ayırt edip dışarı structured sonuç veriyoruz.
    let outcome = tokio::task::spawn_blocking(|| -> UpdateCheckOutcome {
        let Ok(out) = std::process::Command::new("curl")
            .args([
                "-sL",
                "-w",
                "\n%{http_code}",
                "-H",
                "Accept: application/vnd.github+json",
                "-H",
                "User-Agent: HekaDrop-UpdateCheck",
                "--max-time",
                "10",
                "https://api.github.com/repos/YatogamiRaito/HekaDrop/releases/latest",
            ])
            .output()
        else {
            return UpdateCheckOutcome::NetworkError;
        };
        if !out.status.success() {
            return UpdateCheckOutcome::NetworkError;
        }
        // Gövdeden HTTP kodunu ayıkla (son satır `-w` ile eklendi).
        let body_full = String::from_utf8_lossy(&out.stdout);
        let (body, code) = match body_full.rsplit_once('\n') {
            Some((b, c)) => (b, c.trim()),
            None => (body_full.as_ref(), ""),
        };
        match code {
            "403" => {
                // GitHub 403 yalnız rate-limit değildir: abuse detection,
                // eksik/yanlış User-Agent veya kurumsal proxy blokları da aynı
                // kodu döndürür. Body'de "rate limit" ifadesi varsa gerçekten
                // rate-limit'tir; aksi halde kullanıcıya genel API hatası
                // gösterip detayı kısaltılmış body ile veriyoruz (debug için).
                let body_lower = body.to_lowercase();
                if body_lower.contains("rate limit") || body_lower.contains("api rate limit") {
                    return UpdateCheckOutcome::RateLimited;
                }
                // Body'yi 200 char ile sınırla (char-safe, UTF-8 boundary sağlam).
                let snippet: String = body.chars().take(200).collect();
                return UpdateCheckOutcome::ApiError(format!("403: {}", snippet));
            }
            "200" => {}
            other if !other.is_empty() => {
                return UpdateCheckOutcome::ApiError(format!("HTTP {}", other));
            }
            _ => return UpdateCheckOutcome::NetworkError,
        }
        let json: serde_json::Value = match serde_json::from_str(body) {
            Ok(j) => j,
            Err(e) => return UpdateCheckOutcome::ApiError(format!("JSON: {}", e)),
        };
        let tag = match json.get("tag_name").and_then(|v| v.as_str()) {
            Some(t) => t.to_string(),
            None => return UpdateCheckOutcome::ApiError("tag_name yok".into()),
        };
        let url = json
            .get("html_url")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let latest = tag.trim_start_matches('v');
        if semver_less(env!("CARGO_PKG_VERSION"), latest) {
            UpdateCheckOutcome::Available { tag, url }
        } else {
            UpdateCheckOutcome::Current
        }
    })
    .await
    .unwrap_or(UpdateCheckOutcome::NetworkError);

    // Mevcut dialog UX'i (Available / Current) korunur; UI push status bar'a
    // ek bilgi (kind-coded) verir. İki kanal de aynı event üzerinde tetikleniyor
    // — kullanıcı dialog'u kapatsa bile status div'i durumu gösterir.
    match &outcome {
        UpdateCheckOutcome::Available { tag, url } => {
            ui::show_info(
                i18n::t("dialog.update.title"),
                &i18n::tf("dialog.update.available", &[current, tag, url]),
            );
        }
        UpdateCheckOutcome::Current => {
            ui::show_info(
                i18n::t("notify.app_name"),
                &i18n::tf("dialog.update.latest", &[current]),
            );
        }
        _ => {}
    }
    render_update_outcome(outcome);
}

fn render_update_outcome(outcome: UpdateCheckOutcome) {
    // Hard-coded TR string'ler → i18n key'leri. Mesaj içerikleri src/i18n.rs'te
    // `update.error.*` / `update.status.*` altında tanımlı; burada yalnızca
    // key referansı tutuyoruz → TR/EN otomatik çözülür.
    match outcome {
        UpdateCheckOutcome::Disabled => {
            push_update_status(i18n::t("update.error.disabled"), "info");
        }
        UpdateCheckOutcome::Current => {
            push_update_status(i18n::t("update.status.up_to_date"), "info");
        }
        UpdateCheckOutcome::Available { tag, url } => {
            let msg = i18n::tf("update.status.new_version", &[&tag]);
            // URL'yi mesaja iliştiriyoruz — i18n string'i sürüm taglına odaklı,
            // link satır içi bilgi olarak kalıyor.
            push_update_status(&format!("{} — {}", msg, url), "success");
        }
        UpdateCheckOutcome::NetworkError => {
            push_update_status(i18n::t("update.error.network"), "error");
        }
        UpdateCheckOutcome::RateLimited => {
            push_update_status(i18n::t("update.error.rate_limit"), "error");
        }
        UpdateCheckOutcome::ApiError(detail) => {
            // Generic error + detay: detay debug/bug report için değerli, ana
            // mesaj i18n'den gelir.
            push_update_status(
                &format!("{} ({})", i18n::t("update.error.generic"), detail),
                "error",
            );
        }
    }
}

/// Basit nokta-ayrılmış sayısal sürüm karşılaştırması: "0.1.0" < "0.2.0" < "1.0.0".
fn semver_less(current: &str, latest: &str) -> bool {
    let parse = |s: &str| -> Vec<u32> { s.split('.').filter_map(|p| p.parse().ok()).collect() };
    parse(current) < parse(latest)
}

/// Bırakılan path'leri düzleştir:
///   - Dosya → olduğu gibi
///   - Dizin → içindeki tüm dosyalar (recursive)
///   - Symlink dizin → takip ETMEZ (döngü koruması; o path atlanır)
///
/// Okuma hatası olan alt dizinler sessizce atlanır (tracing::warn log'u ile).
/// Stack-based BFS; rekürsif çağrı yok, derin ağaçlarda stack overflow yok.
fn expand_folder_drops(dropped: Vec<std::path::PathBuf>) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let mut stack: Vec<std::path::PathBuf> = dropped;

    while let Some(p) = stack.pop() {
        // symlink_metadata symbolik bağları takip ETMEZ — dizin gibi görünen
        // symlink'ler "symlink" olarak kalır, aşağıda elendirilir.
        let meta = match std::fs::symlink_metadata(&p) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(
                    "[drop] stat hatası atlanıyor: {} ({})",
                    crate::log_redact::path_basename(&p),
                    e
                );
                continue;
            }
        };
        if meta.file_type().is_symlink() {
            tracing::warn!(
                "[drop] symlink atlanıyor: {}",
                crate::log_redact::path_basename(&p)
            );
            continue;
        }
        if meta.is_dir() {
            match std::fs::read_dir(&p) {
                Ok(entries) => {
                    for entry in entries.flatten() {
                        stack.push(entry.path());
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        "[drop] dizin okuma hatası: {} ({})",
                        crate::log_redact::path_basename(&p),
                        e
                    );
                }
            }
        } else if meta.is_file() {
            out.push(p);
        }
        // Diğer durumlar (socket, device vb.) atla.
    }

    out
}

fn relative_time(secs: u64) -> String {
    let (key, val) = if secs < 60 {
        ("time.seconds_ago", secs)
    } else if secs < 3600 {
        ("time.minutes_ago", secs / 60)
    } else if secs < 86400 {
        ("time.hours_ago", secs / 3600)
    } else {
        ("time.days_ago", secs / 86400)
    };
    i18n::tf(key, &[&val.to_string()])
}

fn human_size(bytes: i64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    // HUMAN: byte sayısını okunur birime çevirmek için precision loss kabul.
    #[allow(clippy::cast_precision_loss)]
    let mut n = bytes as f64;
    let mut i = 0;
    while n >= 1024.0 && i < UNITS.len() - 1 {
        n /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{} B", bytes)
    } else {
        format!("{:.1} {}", n, UNITS[i])
    }
}

#[cfg(target_os = "macos")]
fn toggle_login_item() {
    let Ok(home) = std::env::var("HOME") else {
        ui::notify("HekaDrop", "HOME bulunamadı");
        return;
    };
    let plist_path = format!("{}/Library/LaunchAgents/com.sourvice.hekadrop.plist", home);
    let plist_exists = std::path::Path::new(&plist_path).exists();

    if plist_exists {
        let _ = std::process::Command::new("launchctl")
            .args(["unload", &plist_path])
            .output();
        let _ = std::fs::remove_file(&plist_path);
        ui::notify(
            "HekaDrop",
            "Otomatik başlatma kapatıldı (launchd agent kaldırıldı)",
        );
        return;
    }

    let app_path = "/Applications/HekaDrop.app";
    if !std::path::Path::new(app_path).exists() {
        ui::show_info(
            "HekaDrop — otomatik başlatma",
            &format!(
                "Önce HekaDrop.app'i {} dizinine kopyalayın.\n\nTerminal'den:  make install",
                app_path
            ),
        );
        return;
    }

    let plist_template = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.sourvice.hekadrop</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Applications/HekaDrop.app/Contents/MacOS/hekadrop</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ProcessType</key>
    <string>Interactive</string>
    <key>StandardOutPath</key>
    <string>/tmp/hekadrop.stdout.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/hekadrop.stderr.log</string>
    <key>ThrottleInterval</key>
    <integer>10</integer>
</dict>
</plist>
"#;

    if let Some(parent) = std::path::Path::new(&plist_path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Err(e) = std::fs::write(&plist_path, plist_template) {
        ui::show_info(
            "HekaDrop",
            &format!("plist yazılamadı: {}\nKonum: {}", e, plist_path),
        );
        return;
    }

    let _ = std::process::Command::new("launchctl")
        .args(["load", "-w", &plist_path])
        .output();
    ui::notify(
        "HekaDrop",
        "Otomatik başlatma açıldı (launchd agent yüklendi)",
    );
}

/// macOS / Linux / Windows dışındaki platformlar için stub.
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn toggle_login_item() {
    ui::show_info(
        "HekaDrop — otomatik başlatma",
        "Bu platformda otomatik başlatma henüz desteklenmiyor.",
    );
}

/// Windows: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` Registry
/// anahtarına "HekaDrop" değerini yazar ya da kaldırır. Binary yolu
/// `current_exe()` ile alınır (tırnak içine alınarak; Program Files gibi
/// boşluklu yollara dayanıklı).
#[cfg(target_os = "windows")]
fn toggle_login_item() {
    use crate::platform::win::to_wide;
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::System::Registry::{
        RegCloseKey, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, HKEY,
        HKEY_CURRENT_USER, KEY_READ, KEY_WRITE, REG_SZ,
    };

    const SUBKEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
    const VALUE: &str = "HekaDrop";

    let subkey_w = to_wide(SUBKEY);
    let value_w = to_wide(VALUE);

    // Mevcut durumu yokla (varsa sil → toggle off).
    let mut hkey = HKEY::default();
    // SAFETY: `subkey_w` ve `value_w` `to_wide` ile üretilmiş NUL-terminated
    // local `Vec<u16>`'lar; blok süresince canlı. `&mut hkey` lokal HKEY'in
    // exclusive borrow'u — `RegOpenKeyExW` başarılı olursa açılan handle'ı
    // yazar; `RegCloseKey` ile her iki dalda da kapatıyoruz. `RegQueryValueExW`
    // pData/pcbData için `None`/`Some(&mut size)` veriyor, bu yalnızca
    // değerin varlığını/uzunluğunu sorgular, buffer over-write riski yok.
    let exists = unsafe {
        let rc = RegOpenKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(subkey_w.as_ptr()),
            None,
            KEY_READ,
            &mut hkey,
        );
        if rc != ERROR_SUCCESS {
            false
        } else {
            let mut size: u32 = 0;
            let q = RegQueryValueExW(
                hkey,
                PCWSTR(value_w.as_ptr()),
                None,
                None,
                None,
                Some(&mut size),
            );
            let _ = RegCloseKey(hkey);
            q == ERROR_SUCCESS
        }
    };

    if exists {
        let mut hkey = HKEY::default();
        // SAFETY: `subkey_w` ve `value_w` `to_wide`'dan gelen NUL-terminated
        // local buffer'lar; blok süresince canlı. `&mut hkey` lokal HKEY'e
        // exclusive borrow. Açılan handle başarı durumunda `RegCloseKey` ile
        // kapatılıyor; başarısız `RegOpenKeyExW`'da handle yazılmaz, kapatma
        // gerekmez. `RegDeleteValueW` yalnızca PCWSTR'i NUL'a kadar okur.
        unsafe {
            let rc = RegOpenKeyExW(
                HKEY_CURRENT_USER,
                PCWSTR(subkey_w.as_ptr()),
                None,
                KEY_WRITE,
                &mut hkey,
            );
            if rc == ERROR_SUCCESS {
                let del_rc = RegDeleteValueW(hkey, PCWSTR(value_w.as_ptr()));
                let _ = RegCloseKey(hkey);
                if del_rc == ERROR_SUCCESS {
                    ui::notify(
                        "HekaDrop",
                        "Otomatik başlatma kapatıldı (Registry Run anahtarı kaldırıldı)",
                    );
                } else {
                    ui::show_info(
                        "HekaDrop",
                        &format!("Registry değeri silinemedi (err={:?})", del_rc),
                    );
                }
                return;
            }
        }
        ui::show_info(
            "HekaDrop",
            "Registry anahtarına yazma hakkı yok (HKCU normalde açık olur).",
        );
        return;
    }

    // Yoksa ekle — current_exe path'ini tırnak içine al.
    // path.display() UTF-8 olmayan byte'ları lossy dönüştürebilir; OsStr'in
    // wide encoding'ini kullanarak lossless UTF-16 üretiyoruz.
    // Err binding'i `e` format!'da kullanılıyor — `let-else` formunda Err
    // değişkenine ulaşılamaz; bu match form bilinçli tutuluyor. clippy
    // refactor önerir ama burada error context detayını koruma tercihi.
    #[allow(clippy::manual_let_else, clippy::single_match_else)]
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            ui::show_info(
                "HekaDrop — otomatik başlatma",
                &format!("current_exe alınamadı: {}", e),
            );
            return;
        }
    };
    let mut cmdline_w: Vec<u16> = Vec::with_capacity(exe.as_os_str().len() + 3);
    cmdline_w.push(u16::from(b'"'));
    cmdline_w.extend(exe.as_os_str().encode_wide());
    cmdline_w.push(u16::from(b'"'));
    cmdline_w.push(0);
    // REG_SZ: byte uzunluğu (null dahil).
    let byte_len = cmdline_w.len() * std::mem::size_of::<u16>();

    // SAFETY: `subkey_w`/`value_w`/`cmdline_w` NUL-terminated local
    // `Vec<u16>`'lar, blok süresince canlı. `byte_len = cmdline_w.len() *
    // size_of::<u16>()` yani `from_raw_parts`'a verdiğimiz `u8` slice tam
    // olarak `cmdline_w`'in bellek bölgesini kapsıyor (alignment u16 ⊇ u8,
    // overflow yok — `with_capacity` zaten allocate etti). REG_SZ için
    // byte uzunluğu null-terminator dahil verilir; bu doğru. `&mut hkey`
    // lokal değişkene exclusive borrow; handle başarılı openda `RegCloseKey`
    // ile, başarısız openda hiç yazılmadığı için kapatılmaz.
    unsafe {
        let mut hkey = HKEY::default();
        let rc = RegOpenKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(subkey_w.as_ptr()),
            None,
            KEY_WRITE,
            &mut hkey,
        );
        if rc != ERROR_SUCCESS {
            ui::show_info(
                "HekaDrop",
                &format!("Registry Run anahtarı açılamadı (err={:?})", rc),
            );
            return;
        }
        let set_rc = RegSetValueExW(
            hkey,
            PCWSTR(value_w.as_ptr()),
            None,
            REG_SZ,
            Some(std::slice::from_raw_parts(
                cmdline_w.as_ptr() as *const u8,
                byte_len,
            )),
        );
        let _ = RegCloseKey(hkey);
        if set_rc == ERROR_SUCCESS {
            ui::notify(
                "HekaDrop",
                "Otomatik başlatma açıldı (Registry Run anahtarı yazıldı)",
            );
        } else {
            ui::show_info(
                "HekaDrop",
                &format!("Registry değeri yazılamadı (err={:?})", set_rc),
            );
        }
    }
}

/// Linux: systemd --user tabanlı otomatik başlatma.
///
/// `~/.config/systemd/user/hekadrop.service` dosyasını yazar ya da kaldırır.
/// Gerçek binary yolu `std::env::current_exe()` ile alınır — `cargo run` ya da
/// kurulu binary olsun aynı kalır.
#[cfg(target_os = "linux")]
fn toggle_login_item() {
    let Ok(home) = std::env::var("HOME") else {
        ui::notify("HekaDrop", "HOME bulunamadı");
        return;
    };

    let unit_dir = std::path::PathBuf::from(&home).join(".config/systemd/user");
    let unit_path = unit_dir.join("hekadrop.service");
    let unit_name = "hekadrop.service";

    if unit_path.exists() {
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "disable", "--now", unit_name])
            .output();
        let _ = std::fs::remove_file(&unit_path);
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "daemon-reload"])
            .output();
        ui::notify(
            "HekaDrop",
            "Otomatik başlatma kapatıldı (systemd user unit kaldırıldı)",
        );
        return;
    }

    // Err binding'i `e` format!'da kullanılıyor — `let-else` formunda Err
    // değişkenine ulaşılamaz; bu match form bilinçli tutuluyor. clippy
    // refactor önerir ama burada error context detayını koruma tercihi.
    #[allow(clippy::manual_let_else, clippy::single_match_else)]
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            ui::show_info(
                "HekaDrop — otomatik başlatma",
                &format!("current_exe alınamadı: {}", e),
            );
            return;
        }
    };

    let unit = format!(
        "[Unit]\n\
         Description=HekaDrop — Quick Share alıcı/gönderici\n\
         After=graphical-session.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart={}\n\
         Restart=on-failure\n\
         RestartSec=10\n\
         \n\
         [Install]\n\
         WantedBy=default.target\n",
        exe.display()
    );

    if let Err(e) = std::fs::create_dir_all(&unit_dir) {
        ui::show_info(
            "HekaDrop",
            &format!(
                "systemd user dizini oluşturulamadı: {}\n{}",
                e,
                unit_dir.display()
            ),
        );
        return;
    }
    if let Err(e) = std::fs::write(&unit_path, unit) {
        ui::show_info(
            "HekaDrop",
            &format!("service dosyası yazılamadı: {}\n{}", e, unit_path.display()),
        );
        return;
    }

    let _ = std::process::Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .output();
    let enable = std::process::Command::new("systemctl")
        .args(["--user", "enable", "--now", unit_name])
        .output();
    match enable {
        Ok(o) if o.status.success() => ui::notify(
            "HekaDrop",
            "Otomatik başlatma açıldı (systemd user unit yüklendi)",
        ),
        Ok(o) => ui::show_info(
            "HekaDrop",
            &format!(
                "systemctl --user enable hata:\n{}",
                String::from_utf8_lossy(&o.stderr).trim()
            ),
        ),
        Err(e) => ui::show_info("HekaDrop", &format!("systemctl çalıştırılamadı: {}", e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn tmp_dir(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("hekadrop-test-{}-{}", name, std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn expand_drops_duz_dosya_listesi_aynen_doner() {
        let dir = tmp_dir("expand-files");
        let f1 = dir.join("a.txt");
        let f2 = dir.join("b.txt");
        fs::write(&f1, b"a").unwrap();
        fs::write(&f2, b"b").unwrap();

        let out = expand_folder_drops(vec![f1.clone(), f2.clone()]);
        assert_eq!(out.len(), 2);
        assert!(out.contains(&f1));
        assert!(out.contains(&f2));
    }

    #[test]
    fn expand_drops_klasoru_acar_recursive() {
        let root = tmp_dir("expand-dir");
        let sub = root.join("sub");
        fs::create_dir(&sub).unwrap();
        fs::write(root.join("top.txt"), b"t").unwrap();
        fs::write(sub.join("inner.txt"), b"i").unwrap();

        let out = expand_folder_drops(vec![root.clone()]);
        assert_eq!(out.len(), 2);
        let names: Vec<String> = out
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert!(names.contains(&"top.txt".to_string()));
        assert!(names.contains(&"inner.txt".to_string()));
    }

    #[test]
    fn expand_drops_karma_dosya_klasor_birlikte() {
        let root = tmp_dir("expand-mixed");
        let plain = root.join("plain.txt");
        let dir = root.join("folder");
        fs::write(&plain, b"p").unwrap();
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("in1.txt"), b"1").unwrap();
        fs::write(dir.join("in2.txt"), b"2").unwrap();

        let out = expand_folder_drops(vec![plain.clone(), dir.clone()]);
        assert_eq!(out.len(), 3);
    }

    #[test]
    fn expand_drops_symlink_atlar_dongu_olusmaz() {
        // Unix-only test — Windows'ta junction/symlink yaratmak farklı API.
        #[cfg(unix)]
        {
            let root = tmp_dir("expand-symlink");
            let real = root.join("real");
            fs::create_dir(&real).unwrap();
            fs::write(real.join("file.txt"), b"f").unwrap();

            // Symlink real → root (döngü yaratır, işlenirse sonsuz recursion)
            let link = root.join("link");
            std::os::unix::fs::symlink(&root, &link).unwrap();

            let out = expand_folder_drops(vec![root.clone()]);
            // file.txt sayılmalı; symlink (link) atlanmalı → sonsuz değil
            let names: Vec<String> = out
                .iter()
                .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
                .collect();
            assert!(names.contains(&"file.txt".to_string()));
            // link'in kendisi file olarak eklenmemeli (symlink, atlandı)
            assert!(!names.contains(&"link".to_string()));
        }
    }

    #[test]
    fn expand_drops_bos_listeden_bos_doner() {
        let out = expand_folder_drops(vec![]);
        assert!(out.is_empty());
    }

    #[test]
    fn expand_drops_mevcut_olmayan_path_atlar() {
        let fake = std::path::PathBuf::from("/tmp/hekadrop-nonexistent-xyzzy-123");
        let out = expand_folder_drops(vec![fake]);
        assert!(out.is_empty());
    }
}
