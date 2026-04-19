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
use wry::{DragDropEvent, WebViewBuilder};

mod config;
mod connection;
mod crypto;
mod discovery;
mod error;
mod frame;
mod mdns;
mod payload;
mod platform;
mod secure;
mod sender;
mod server;
mod settings;
mod state;
mod stats;
mod ui;
mod ukey2;

static RUNTIME: OnceLock<Handle> = OnceLock::new();

#[allow(
    clippy::all,
    non_snake_case,
    non_camel_case_types,
    dead_code,
    rustdoc::invalid_html_tags,
    rustdoc::broken_intra_doc_links
)]
pub mod securegcm {
    include!(concat!(env!("OUT_DIR"), "/securegcm.rs"));
}

#[allow(
    clippy::all,
    non_snake_case,
    non_camel_case_types,
    dead_code,
    rustdoc::invalid_html_tags,
    rustdoc::broken_intra_doc_links
)]
pub mod securemessage {
    include!(concat!(env!("OUT_DIR"), "/securemessage.rs"));
}

#[allow(
    clippy::all,
    non_snake_case,
    non_camel_case_types,
    dead_code,
    rustdoc::invalid_html_tags,
    rustdoc::broken_intra_doc_links
)]
pub mod location {
    pub mod nearby {
        pub mod connections {
            include!(concat!(env!("OUT_DIR"), "/location.nearby.connections.rs"));
        }
        pub mod proto {
            pub mod sharing {
                include!(concat!(
                    env!("OUT_DIR"),
                    "/location.nearby.proto.sharing.rs"
                ));
            }
        }
    }
}

#[allow(
    clippy::all,
    non_snake_case,
    non_camel_case_types,
    dead_code,
    rustdoc::invalid_html_tags,
    rustdoc::broken_intra_doc_links
)]
pub mod sharing {
    pub mod nearby {
        include!(concat!(env!("OUT_DIR"), "/sharing.nearby.rs"));
    }
}

const WINDOW_HTML: &str = include_str!("../resources/window.html");

async fn async_main() -> Result<()> {
    let device_name = state::get().settings.read().resolved_device_name();
    info!("HekaDrop başlıyor — cihaz: {}", device_name);

    let listener = server::start_listener().await?;
    let port = listener.local_addr()?.port();
    state::set_listen_port(port);
    info!("TCP dinleniyor: 0.0.0.0:{}", port);

    let _mdns_handle = mdns::advertise(&device_name, port)?;

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
    setup_logging();

    state::init(settings::Settings::load());

    std::thread::Builder::new()
        .name("hekadrop-async".into())
        .spawn(|| {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("tokio runtime kurulamadı");
            let _ = RUNTIME.set(rt.handle().clone());
            if let Err(e) = rt.block_on(async_main()) {
                tracing::error!("async_main hata: {:?}", e);
                std::process::exit(1);
            }
        })
        .expect("async thread başlatılamadı");

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
fn setup_logging() {
    use tracing_appender::rolling::{RollingFileAppender, Rotation};
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("hekadrop=info"));

    let log_dir = platform::logs_dir();
    let _ = std::fs::create_dir_all(&log_dir);

    // Başlangıç temizliği — appender açılmadan önce diski kontrol altına al.
    truncate_oversized_logs(&log_dir, 10 * 1024 * 1024);
    cleanup_old_logs(&log_dir, 3);

    let file_appender = RollingFileAppender::builder()
        .rotation(Rotation::DAILY)
        .filename_prefix("hekadrop")
        .filename_suffix("log")
        .max_log_files(3)
        .build(&log_dir)
        .expect("log appender kurulamadı");

    let (file_writer, guard) = tracing_appender::non_blocking(file_appender);
    Box::leak(Box::new(guard));

    let stdout_layer = fmt::layer().with_writer(std::io::stdout);
    let file_layer = fmt::layer().with_writer(file_writer).with_ansi(false);

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
    let title_item = MenuItem::new(format!("HekaDrop — {}", device_name), false, None);
    let status_item = MenuItem::new("Hazır", false, None);
    let show_window_item = MenuItem::new("Pencereyi göster", true, None);
    let send_item = MenuItem::new("Dosya gönder…", true, None);
    let cancel_item = MenuItem::new("Aktarımı iptal et", false, None);
    let auto_accept_item = CheckMenuItem::new("Otomatik kabul", true, auto_accept_initial, None);
    let history_item = MenuItem::new("Son aktarımları göster", true, None);
    let open_downloads = MenuItem::new("İndirme klasörünü aç", true, None);
    let open_config = MenuItem::new("Yapılandırma dosyasını göster", true, None);
    let login_item = MenuItem::new("Başlangıçta aç (Launchd)", true, None);
    let about_item = MenuItem::new("Hakkında", true, None);
    let quit_item = MenuItem::new("Çıkış", true, None);

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

    let tray = TrayIconBuilder::new()
        .with_menu(Box::new(tray_menu))
        .with_title("⇄")
        .with_tooltip("HekaDrop")
        .build()
        .expect("tray icon oluşturulamadı");

    // Ana pencere + WebView
    let window = WindowBuilder::new()
        .with_title("HekaDrop")
        .with_inner_size(tao::dpi::LogicalSize::new(340.0, 460.0))
        .with_min_inner_size(tao::dpi::LogicalSize::new(320.0, 400.0))
        .with_resizable(false)
        .with_visible(true)
        .build(&event_loop)
        .expect("window oluşturulamadı");

    let builder = WebViewBuilder::new()
        .with_html(WINDOW_HTML)
        .with_ipc_handler(|req| {
            let cmd = req.into_body();
            handle_ipc(&cmd);
        })
        .with_drag_drop_handler(|event| {
            if let DragDropEvent::Drop { paths, .. } = event {
                if !paths.is_empty() {
                    info!("[ui] drop: {} dosya", paths.len());
                    if let Some(rt) = RUNTIME.get() {
                        rt.spawn(initiate_send_flow_with(paths));
                    }
                }
            }
            true
        });

    // Linux (GTK): wry WebView bir gtk::Container içine monte edilmelidir;
    // raw-window-handle yolu desteklenmez. macOS/Windows'ta `.build(&window)`.
    #[cfg(target_os = "linux")]
    let webview = {
        use tao::platform::unix::WindowExtUnix;
        use wry::WebViewBuilderExtUnix;
        let vbox = window
            .default_vbox()
            .expect("tao pencere gtk_vbox döndürmedi");
        builder.build_gtk(vbox).expect("webview oluşturulamadı")
    };
    #[cfg(not(target_os = "linux"))]
    let webview = builder.build(&window).expect("webview oluşturulamadı");

    let menu_channel = MenuEvent::receiver();
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
            ui::notify(
                "HekaDrop",
                "Arkaplanda çalışıyor — menü çubuğundan devam edebilirsin",
            );
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
            let _ = tray.set_tooltip(Some(format!("HekaDrop — {}", status_text)));
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

        // Tray menü olayları
        while let Ok(ev) = menu_channel.try_recv() {
            if ev.id == quit_item_id {
                info!("kullanıcı çıkışı seçti");
                std::process::exit(0);
            } else if ev.id == show_window_item_id {
                state::request_show_window();
            } else if ev.id == send_item_id {
                if let Some(rt) = RUNTIME.get() {
                    rt.spawn(initiate_send_flow());
                }
            } else if ev.id == cancel_item_id {
                state::request_cancel();
                ui::notify(
                    "HekaDrop",
                    "İptal istendi, aktif transferler sonlandırılıyor…",
                );
            } else if ev.id == open_downloads_id {
                open_downloads_folder();
            } else if ev.id == open_config_id {
                open_config_file();
            } else if ev.id == auto_accept_id {
                let new_val = auto_accept_item.is_checked();
                {
                    let st = state::get();
                    let mut s = st.settings.write();
                    s.auto_accept = new_val;
                    let _ = s.save();
                }
                info!("auto_accept → {}", new_val);
                ui::notify(
                    "HekaDrop",
                    if new_val {
                        "Otomatik kabul açık"
                    } else {
                        "Otomatik kabul kapalı"
                    },
                );
            } else if ev.id == login_item_id {
                toggle_login_item();
            } else if ev.id == history_item_id {
                show_history();
            } else if ev.id == about_item_id {
                ui::notify("HekaDrop", "Quick Share alıcısı/göndericisi — Rust/macOS");
            }
        }
    });
}

fn handle_ipc(cmd: &str) {
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
        let mut s = st.settings.write();
        s.remove_trusted(name);
        let _ = s.save();
        drop(s);
        push_trusted_to_ui();
        ui::notify("HekaDrop", &format!("Güven kaldırıldı: {}", name));
        return;
    }
    match cmd {
        "send" => {
            if let Some(rt) = RUNTIME.get() {
                rt.spawn(initiate_send_flow());
            }
        }
        "settings_get" => {
            push_settings_to_ui();
            push_trusted_to_ui();
        }
        "trusted_refresh" => push_trusted_to_ui(),
        "stats_refresh" => push_stats_to_ui(),
        "stats_reset" => {
            let st = state::get();
            let mut s = st.stats.write();
            *s = stats::Stats::default();
            let _ = s.save();
            drop(s);
            push_stats_to_ui();
            ui::notify("HekaDrop", "İstatistikler sıfırlandı");
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
            let mut s = st.settings.write();
            s.trusted_devices.clear();
            let _ = s.save();
            drop(s);
            push_trusted_to_ui();
            ui::notify("HekaDrop", "Tüm güvenilen cihazlar temizlendi");
        }
        "history_refresh" => push_history_to_ui(),
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
            ui::notify("HekaDrop", "Arkaplana gizlendi — menü çubuğundan aç");
        }
        "quit" => std::process::exit(0),
        other => tracing::warn!("bilinmeyen ipc: {}", other),
    }
}

fn handle_settings_save(json: &str) {
    #[derive(serde::Deserialize, Debug)]
    struct Incoming {
        device_name: Option<String>,
        download_dir: Option<String>,
        auto_accept: bool,
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
        let mut s = st.settings.write();
        s.device_name = parsed.device_name.filter(|x| !x.is_empty());
        s.download_dir = parsed.download_dir.map(std::path::PathBuf::from);
        s.auto_accept = parsed.auto_accept;
        let _ = s.save();
    }
    info!("[ui] ayarlar güncellendi");
    state::enqueue_js("window.showSaved && window.showSaved()".into());
    ui::notify("HekaDrop", "Ayarlar kaydedildi");
}

fn push_settings_to_ui() {
    let st = state::get();
    let s = st.settings.read();
    let resolved_name = s.resolved_device_name();
    let resolved_dl = s.resolved_download_dir().to_string_lossy().to_string();
    let payload = serde_json::json!({
        "device_name": s.device_name.clone().unwrap_or(resolved_name),
        "download_dir": s.download_dir.as_ref().map(|p| p.to_string_lossy().to_string()).unwrap_or(resolved_dl),
        "auto_accept": s.auto_accept,
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
        "henüz yok".to_string()
    };
    let last_use_human = if s.last_use_epoch > 0 {
        relative_time(now.saturating_sub(s.last_use_epoch))
    } else {
        "henüz yok".to_string()
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
    // Bug #32: Settings artık TrustedDevice struct listesi tutar; UI'ya
    // `name (id_kisa)` biçiminde görünüm string'leri gönderilir (applyTrusted
    // JS sözleşmesi string[] olarak korundu).
    let names: Vec<String> = st.settings.read().trusted_display_list();
    let payload =
        serde_json::Value::Array(names.into_iter().map(serde_json::Value::String).collect());
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
        let _ = state::get().settings.read().save();
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
        state::ProgressState::Idle => "Hazır".to_string(),
        state::ProgressState::Receiving {
            device,
            file,
            percent,
        } => format!("Alınıyor ({}): {} %{}", device, file, percent),
        state::ProgressState::Completed { file } => format!("Tamamlandı: {}", file),
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

    ui::notify("HekaDrop", "Yakındaki cihazlar taranıyor…");

    let own_port = state::listen_port();
    let devices = match discovery::scan(Duration::from_secs(3), own_port).await {
        Ok(v) => v,
        Err(e) => {
            ui::show_info("HekaDrop — keşif hatası", &format!("{:#}", e));
            return;
        }
    };

    if devices.is_empty() {
        ui::show_info(
            "HekaDrop",
            "Yakında Quick Share cihazı bulunamadı.\n\nAndroid'de: Ayarlar → Bağlı cihazlar → Quick Share → görünürlüğü \"Herkes\" yap ve ekranı açık tut.",
        );
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
        "HekaDrop",
        &format!("{} hedefine gönderiliyor: {}", device.name, summary),
    );

    let req = sender::SendRequest {
        device: device.clone(),
        files,
    };
    match sender::send(req).await {
        Ok(_) => {
            ui::notify(
                "HekaDrop",
                &format!("Gönderim tamamlandı → {}", device.name),
            );
        }
        Err(e) => {
            tracing::warn!("send hatası: {:#}", e);
            ui::show_info("HekaDrop — gönderim", &format!("{:#}", e));
        }
    }
}

fn show_history() {
    let items = state::read_history();
    if items.is_empty() {
        ui::show_info("Son aktarımlar", "Henüz aktarım yok.");
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
    ui::show_info("Son aktarımlar", &body);
}

async fn check_update_async() {
    let current = env!("CARGO_PKG_VERSION");
    let fetched = tokio::task::spawn_blocking(|| -> Option<(String, String)> {
        let out = std::process::Command::new("curl")
            .args([
                "-sL",
                "-H",
                "Accept: application/vnd.github+json",
                "-H",
                "User-Agent: HekaDrop-UpdateCheck",
                "--max-time",
                "10",
                "https://api.github.com/repos/YatogamiRaito/HekaDrop/releases/latest",
            ])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let json: serde_json::Value = serde_json::from_slice(&out.stdout).ok()?;
        let tag = json.get("tag_name")?.as_str()?.to_string();
        let url = json.get("html_url")?.as_str()?.to_string();
        Some((tag, url))
    })
    .await
    .ok()
    .flatten();

    match fetched {
        Some((tag, url)) => {
            let latest = tag.trim_start_matches('v');
            if semver_less(current, latest) {
                ui::show_info(
                    "HekaDrop — Güncelleme var",
                    &format!("Mevcut: v{}\nYeni sürüm: {}\n\n{}", current, tag, url),
                );
            } else {
                ui::show_info(
                    "HekaDrop",
                    &format!("En güncel sürümü kullanıyorsun (v{}).", current),
                );
            }
        }
        None => {
            ui::show_info(
                "HekaDrop",
                "Güncelleme kontrolü başarısız.\n\n\
                 Henüz yayınlanmış bir release yoksa (repo özel ise) bu normal.\n\
                 İnternet bağlantını kontrol edip tekrar dene.",
            );
        }
    }
}

/// Basit nokta-ayrılmış sayısal sürüm karşılaştırması: "0.1.0" < "0.2.0" < "1.0.0".
fn semver_less(current: &str, latest: &str) -> bool {
    let parse = |s: &str| -> Vec<u32> { s.split('.').filter_map(|p| p.parse().ok()).collect() };
    parse(current) < parse(latest)
}

fn relative_time(secs: u64) -> String {
    if secs < 60 {
        format!("{} sn önce", secs)
    } else if secs < 3600 {
        format!("{} dk önce", secs / 60)
    } else if secs < 86400 {
        format!("{} sa önce", secs / 3600)
    } else {
        format!("{} gün önce", secs / 86400)
    }
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
        format!("{} B", bytes)
    } else {
        format!("{:.1} {}", n, UNITS[i])
    }
}

#[cfg(target_os = "macos")]
fn toggle_login_item() {
    let home = match std::env::var("HOME") {
        Ok(h) => h,
        Err(_) => {
            ui::notify("HekaDrop", "HOME bulunamadı");
            return;
        }
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
    cmdline_w.push(b'"' as u16);
    cmdline_w.extend(exe.as_os_str().encode_wide());
    cmdline_w.push(b'"' as u16);
    cmdline_w.push(0);
    // REG_SZ: byte uzunluğu (null dahil).
    let byte_len = cmdline_w.len() * std::mem::size_of::<u16>();

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
    let home = match std::env::var("HOME") {
        Ok(h) => h,
        Err(_) => {
            ui::notify("HekaDrop", "HOME bulunamadı");
            return;
        }
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
