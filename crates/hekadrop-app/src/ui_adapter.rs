//! `UiPort` trait'inin app-side concrete implementation'ı. `connection.rs`
//! ve sonraki adımlarda `sender.rs`, `server.rs` bu adapter'ı `Arc<dyn
//! UiPort>` olarak alır.
//!
//! RFC-0001 §5 Adım 5b — `UiAdapter` mevcut `crate::ui::*` fn'lerini
//! ve `crate::i18n::*` çevrimini sarar. Core sadece key + args verir;
//! locale çözümlemesi burada yapılır.
//!
//! # Davranış parity
//!
//! Bu adapter Adım 5b öncesi `connection.rs` içindeki tüm `ui::notify`,
//! `ui::notify_file_received`, `ui::prompt_accept` çağrılarını birebir
//! aynı argümanlarla çağırır — kullanıcıya görünen toast/dialog metni
//! ve timing değişmez. Refactor pure mechanical decoupling.

use async_trait::async_trait;
use hekadrop_core::ui_port::{
    AcceptDecision, FileSummary, FolderPromptSummary, UiNotification, UiPort,
};

/// `connection::PlatformOps` trait'inin app-side concrete impl'i —
/// `crate::platform::open_url` / `crate::platform::copy_to_clipboard`'ı
/// sarar. Connection core'a taşındıktan sonra `Arc<dyn PlatformOps>`
/// olarak `accept_loop`'a geçirilir; core'da `crate::platform` referansı
/// olmaz.
pub(crate) struct PlatformAdapter;

impl PlatformAdapter {
    /// Boş bir `PlatformAdapter` üretir; state taşımayan zero-sized type.
    pub(crate) fn new() -> Self {
        Self
    }
}

impl Default for PlatformAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl hekadrop_core::connection::PlatformOps for PlatformAdapter {
    fn open_url(&self, url: &str) {
        crate::platform::open_url(url);
    }

    fn copy_to_clipboard(&self, text: &str) {
        crate::platform::copy_to_clipboard(text);
    }
}

/// `UiPort` trait'inin app-side concrete impl'i — core'dan gelen
/// `UiNotification` enum'ını `crate::i18n` ile çevirip `crate::ui` toast/dialog
/// fn'lerine delege eder.
pub(crate) struct UiAdapter;

impl UiAdapter {
    /// Boş bir `UiAdapter` üretir; state taşımayan zero-sized type.
    pub(crate) fn new() -> Self {
        Self
    }
}

impl Default for UiAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl UiPort for UiAdapter {
    fn notify(&self, n: UiNotification) {
        match n {
            UiNotification::Toast {
                title_key,
                body_key,
                body_args,
            } => {
                let title = crate::i18n::t(title_key);
                let body = match body_key {
                    Some(key) => {
                        let args_refs: Vec<&str> = body_args.iter().map(String::as_str).collect();
                        crate::i18n::tf(key, &args_refs)
                    }
                    None => String::new(),
                };
                crate::ui::notify(title, &body);
            }
            UiNotification::FileReceived {
                title_key,
                body_key,
                body_args,
                path,
            } => {
                let title = crate::i18n::t(title_key);
                let args_refs: Vec<&str> = body_args.iter().map(String::as_str).collect();
                let body = crate::i18n::tf(body_key, &args_refs);
                crate::ui::notify_file_received(title, &body, path);
            }
            UiNotification::FolderReceived {
                title_key,
                body_key,
                body_args,
                path,
            } => {
                // RFC-0005 PR-F: folder completion toast. Notification altyapısı
                // file ile aynı (`notify-rust` action: open) — ancak file tıklanınca
                // `open_path` dosyayı açar; klasörde aynı çağrı klasörü açar
                // (Finder/Explorer/xdg-open). Reveal action mantıksal olarak
                // duplicate olur (klasör zaten parent'ı olur), o yüzden
                // file path'iyle aynı helper'a delege; OS-bazlı reveal davranışı
                // file için optimal ama klasör için de bozulmaz (parent dir açar).
                //
                // PR #147 high yorumu (Gemini): title key
                // `notification.folder_received.title` `{0}` placeholder içeriyor.
                // `i18n::t` (format'sız) raw string sızdırıyordu. Hem title hem
                // body için `tf` kullan, aynı args setini ver.
                let args_refs: Vec<&str> = body_args.iter().map(String::as_str).collect();
                let title = crate::i18n::tf(title_key, &args_refs);
                let body = crate::i18n::tf(body_key, &args_refs);
                crate::ui::notify_file_received(&title, &body, path);
            }
            UiNotification::ToastRaw { title, body } => {
                crate::ui::notify(&title, &body);
            }
            UiNotification::TrustMigrationHint { device, pin } => {
                let title = crate::i18n::t("trust.migration.title");
                let body = crate::i18n::tf("trust.migration.body", &[&device, &pin]);
                crate::ui::notify(title, &body);
            }
        }
    }

    async fn prompt_accept(
        &self,
        device: &str,
        pin: &str,
        files: &[FileSummary],
        text_count: usize,
        folder: Option<&FolderPromptSummary>,
    ) -> AcceptDecision {
        // Core FileSummary → app ui::FileSummary type conversion. İki struct
        // alan bazında izomorfik; convert burada zorunlu çünkü `crate::ui`
        // core'a sızdırılmıyor (I-1).
        let ui_files: Vec<crate::ui::FileSummary> = files
            .iter()
            .map(|f| crate::ui::FileSummary {
                name: f.name.clone(),
                size: f.size,
            })
            .collect();
        // RFC-0005 PR-F: folder summary'i app-side ui::FolderSummary'e map et.
        // Core type'ı `crate::ui` modülüne sızdırmamak için manual convert.
        let ui_folder = folder.map(|f| crate::ui::FolderSummary {
            root_name: f.root_name.clone(),
            entry_count: f.entry_count,
            total_size: f.total_size,
        });
        let result =
            crate::ui::prompt_accept(device, pin, &ui_files, text_count, ui_folder.as_ref()).await;
        match result {
            Ok(crate::ui::AcceptResult::Accept) => AcceptDecision::Accept,
            Ok(crate::ui::AcceptResult::AcceptAndTrust) => AcceptDecision::AcceptAndTrust,
            Ok(crate::ui::AcceptResult::Reject) | Err(_) => AcceptDecision::Reject,
        }
    }
}
