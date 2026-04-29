//! UI port — connection/sender/server modüllerinin UI'a yönlenmesi
//! için abstract interface. Implementation app crate'inde (`UiAdapter`).
//!
//! RFC-0001 §5 Adım 5b — RFC §9 R1 önerisi: connection handler'ın UI
//! modülüne doğrudan bağımlılığı kırılır; `UiPort` trait üzerinden
//! caller (app) UI yönlendirmesini sağlar. Bu sayede core'a taşınınca
//! UI (tao/wry/notify-rust) sızmaz.
//!
//! # i18n strategy
//!
//! Core sadece `&'static str key` + `Vec<String> args` taşır;
//! i18n çevrim çağrısı app tarafında yapılır.
//! Bu hem i18n modülünü (app-only) core'dan ayrıştırır hem de farklı
//! locale routing'i caller'a bırakır.
//!
//! # Invariant (CLAUDE.md I-1)
//!
//! Bu modül **`crate::*` referansı içermez** — yani app crate'inin
//! modüllerine (`crate::platform`, `crate::ui`, `crate::i18n`,
//! `crate::state`, vs.) doğrudan bağımlı olmamalıdır. Amaç core ↔ app
//! arasında **yönlü** bağımlılığı korumak. `#[async_trait::async_trait]`
//! gibi 3rd party crate path'leri (proc-macro / utility) bu invarianta
//! dahil **değildir** — yalnız in-tree `crate::*` yasak.
//!
//! Pre-commit grep guard (`grep crate:: ui_port.rs`) bu mimari sınırı
//! doğrular; ihlal ederseniz core ↔ app döngüsel bağımlılık doğar.

use std::path::PathBuf;

pub struct FileSummary {
    pub name: String,
    pub size: i64,
}

/// RFC-0005 PR-F — accept dialog enrichment. Peer'dan gelen Introduction'da
/// `application/x-hekadrop-folder` MIME marker bulunduğunda connection
/// handler bu summary'i doldurur; UI dialog body'sinde "klasör — N dosya, X
/// MB" satırı ile dosya yerine klasör bağlamı gösterir.
///
/// `root_name`: peer-controlled string. **Sender tarafında** zaten
/// `folder::sanitize::sanitize_root_name` ile path-traversal/null-byte/depth
/// kontrolünden geçer; receiver UI rendering öncesi ek kontrol gerekmez
/// (CLAUDE.md I-5). `entry_count`: manifest entry sayısı (file + dir);
/// peer-controlled fakat sender tarafında `MAX_FOLDER_ENTRIES` cap altında.
/// `total_size`: bundle içi toplam byte (announced); receiver legacy
/// `MAX_FILE_BYTES` guard'ı zaten Introduction parse aşamasında uyguluyor.
pub struct FolderPromptSummary {
    pub root_name: String,
    pub entry_count: u32,
    pub total_size: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptDecision {
    Reject,
    Accept,
    AcceptAndTrust,
}

pub enum UiNotification {
    /// i18n key'li toast (title + opsiyonel body, body args ile interpolate).
    Toast {
        title_key: &'static str,
        body_key: Option<&'static str>,
        body_args: Vec<String>,
    },
    /// Dosya alımı tamamlandı toast'u — aksiyon butonlu (Aç / Klasörde göster).
    FileReceived {
        title_key: &'static str,
        body_key: &'static str,
        body_args: Vec<String>,
        path: PathBuf,
    },
    /// RFC-0005 PR-F — klasör alımı tamamlandı toast'u. `path` extract sonrası
    /// final klasör konumu; UI bu yola "Klasörü Aç" aksiyonu bağlar
    /// (`platform::open_path`: Finder/Explorer/xdg-open). `body_args` =
    /// `[root_name, entry_count, human_size]`; çevrim app tarafında
    /// `notification.folder_received.body` key'i ile yapılır.
    FolderReceived {
        title_key: &'static str,
        body_key: &'static str,
        body_args: Vec<String>,
        path: PathBuf,
    },
    /// Hardcoded body (legacy — i18n key'e taşınması bekleyen 2 site).
    /// TODO: i18n key haline getir, bu varyantı kaldır.
    ToastRaw { title: String, body: String },
    /// Trust migration heads-up — özel format.
    TrustMigrationHint { device: String, pin: String },
}

#[async_trait::async_trait]
pub trait UiPort: Send + Sync {
    /// Fire-and-forget bildirim. Implementation kuyruk veya doğrudan toast.
    fn notify(&self, n: UiNotification);

    /// User'dan kabul kararı al — modal blocking. `text_count` 0 ise dosya
    /// transferi, ≥1 ise text + dosya kombinasyonu (UI farklı render eder).
    ///
    /// `folder` `Some` iken peer bundle MIME marker ile bir klasör gönderiyor;
    /// UI dialog body'sini "klasör — N dosya, X MB" satırı ile zenginleştirir.
    /// `None` iken mevcut bireysel dosya/metin akışı (RFC-0005 öncesi davranış).
    async fn prompt_accept(
        &self,
        device: &str,
        pin: &str,
        files: &[FileSummary],
        text_count: usize,
        folder: Option<&FolderPromptSummary>,
    ) -> AcceptDecision;
}
