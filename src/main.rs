use anyhow::Result;
use std::sync::OnceLock;
use std::time::Duration;
use tao::event::{Event, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoopBuilder};
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
mod secure;
mod sender;
mod server;
mod settings;
mod state;
mod ui;
mod ukey2;

static RUNTIME: OnceLock<Handle> = OnceLock::new();

#[allow(clippy::all, non_snake_case, non_camel_case_types, dead_code)]
pub mod securegcm {
    include!(concat!(env!("OUT_DIR"), "/securegcm.rs"));
}

#[allow(clippy::all, non_snake_case, non_camel_case_types, dead_code)]
pub mod securemessage {
    include!(concat!(env!("OUT_DIR"), "/securemessage.rs"));
}

#[allow(clippy::all, non_snake_case, non_camel_case_types, dead_code)]
pub mod location {
    pub mod nearby {
        pub mod connections {
            include!(concat!(
                env!("OUT_DIR"),
                "/location.nearby.connections.rs"
            ));
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

#[allow(clippy::all, non_snake_case, non_camel_case_types, dead_code)]
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

/// Hem stdout'a hem de `~/Library/Logs/HekaDrop/hekadrop.log` dosyasına yazar.
///
/// Log şişmesi koruması:
///   - Günlük rotation (her gün yeni dosya)
///   - Maksimum 3 gün tutulur (`max_log_files(3)`)
///   - Başlangıçta 10 MB'ı aşan günlük dosya truncate edilir
///   - Eski (>3 gün) dosyalar mekanik olarak silinir
fn setup_logging() {
    use tracing_appender::rolling::{RollingFileAppender, Rotation};
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("hekadrop=info"));

    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    let log_dir = std::path::PathBuf::from(home).join("Library/Logs/HekaDrop");
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
    let file_layer = fmt::layer()
        .with_writer(file_writer)
        .with_ansi(false);

    tracing_subscriber::registry()
        .with(filter)
        .with(stdout_layer)
        .with(file_layer)
        .init();
}

fn cleanup_old_logs(dir: &std::path::Path, keep_days: u64) {
    let threshold = std::time::SystemTime::now()
        .checked_sub(Duration::from_secs(keep_days * 86400));
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
    let mut event_loop = EventLoopBuilder::new().build();
    // Dock'ta görünme — her zaman sadece menü çubuğunda
    event_loop.set_activation_policy(ActivationPolicy::Accessory);

    let device_name = state::get().settings.read().resolved_device_name();
    let auto_accept_initial = state::get().settings.read().auto_accept;

    // Menü (tray)
    let tray_menu = Menu::new();
    let title_item =
        MenuItem::new(format!("HekaDrop — {}", device_name), false, None);
    let status_item = MenuItem::new("Hazır", false, None);
    let show_window_item = MenuItem::new("Pencereyi göster", true, None);
    let send_item = MenuItem::new("Dosya gönder…", true, None);
    let cancel_item = MenuItem::new("Aktarımı iptal et", false, None);
    let auto_accept_item =
        CheckMenuItem::new("Otomatik kabul", true, auto_accept_initial, None);
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
        .with_inner_size(tao::dpi::LogicalSize::new(320.0, 380.0))
        .with_min_inner_size(tao::dpi::LogicalSize::new(280.0, 320.0))
        .with_resizable(false)
        .with_visible(true)
        .build(&event_loop)
        .expect("window oluşturulamadı");

    let webview = WebViewBuilder::new()
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
        })
        .build(&window)
        .expect("webview oluşturulamadı");

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
        *control_flow = ControlFlow::WaitUntil(
            std::time::Instant::now() + Duration::from_millis(250),
        );

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
                ui::notify("HekaDrop", "İptal istendi, aktif transferler sonlandırılıyor…");
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
                ui::notify(
                    "HekaDrop",
                    "Quick Share alıcısı/göndericisi — Rust/macOS",
                );
            }
        }
    });
}

fn handle_ipc(cmd: &str) {
    info!("[ui] ipc: {}", cmd);
    match cmd {
        "send" => {
            if let Some(rt) = RUNTIME.get() {
                rt.spawn(initiate_send_flow());
            }
        }
        "history" => show_history(),
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

fn open_downloads_folder() {
    let dl = state::get().settings.read().resolved_download_dir();
    let _ = std::process::Command::new("open").arg(&dl).spawn();
}

fn open_config_file() {
    let path = settings::config_path();
    if !path.exists() {
        let _ = state::get().settings.read().save();
    }
    let _ = std::process::Command::new("open").arg("-R").arg(&path).spawn();
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
    let escaped = s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n");
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
            ui::notify("HekaDrop", &format!("Gönderim tamamlandı → {}", device.name));
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
