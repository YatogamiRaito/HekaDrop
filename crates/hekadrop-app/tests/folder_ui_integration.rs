// Test/bench dosyası — production lint'leri test idiomatik kullanımı bozmasın.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::doc_markdown
)]

//! RFC-0005 PR-F — UI integration smoke tests.
//!
//! Bu testler folder transfer pipeline'ının UI dispatch katmanını ve capability
//! gate'ini sabitler. Tüm tests platform-agnostik; gerçek dialog/notification
//! gösterimi platform-specific (CI'da headless ortamlar için skip) ve manuel
//! smoke ile doğrulanır.
//!
//! - `folder_received_notification_payload` — `UiNotification::FolderReceived`
//!   variant'ının i18n key + body args formatı doğru taşınıyor mu.
//! - `folder_accept_prompt_message_format` — `FolderPromptSummary` field'ları
//!   beklenen değerleri taşıyor; downstream rendering pipeline (i18n çevrimi)
//!   için sabit kontrat.
//! - `all_supported_includes_folder_stream_v1` — capabilities.rs assertion
//!   defensive duplicate (bit aktif, peer'a advertise ediliyor).

use hekadrop::capabilities::features;
use hekadrop::ui_port::{FolderPromptSummary, UiNotification};
use std::path::PathBuf;

#[test]
fn folder_received_notification_payload() {
    // RFC-0005 PR-F: connection.rs::finalize_received_payload bundle extract
    // başarısı sonrası `UiNotification::FolderReceived` emit eder. Bu test
    // variant'ın i18n key + body args + path triple'ını sabitler — UI adapter
    // (app-side) bu kontrat üzerine `notification.folder_received.*` keys'i
    // çevirip toast gösterir.
    let final_path = PathBuf::from("/tmp/hekadrop-test/Belgeler");
    let n = UiNotification::FolderReceived {
        title_key: "notification.folder_received.title",
        body_key: "notification.folder_received.body",
        body_args: vec![
            "Belgeler".to_string(),
            "12".to_string(),
            "3.4 MB".to_string(),
        ],
        path: final_path.clone(),
    };
    if let UiNotification::FolderReceived {
        title_key,
        body_key,
        body_args,
        path,
    } = n
    {
        assert_eq!(title_key, "notification.folder_received.title");
        assert_eq!(body_key, "notification.folder_received.body");
        // Body args sırası: [root_name, file_count, human_size].
        // tf("notification.folder_received.title", &args) → "{0}" =
        // root_name; body → "{1} dosya, {2}" pattern. {0} body'de
        // unused — title rendering için reserve.
        assert_eq!(body_args.len(), 3);
        assert_eq!(body_args[0], "Belgeler");
        assert_eq!(body_args[1], "12");
        assert_eq!(body_args[2], "3.4 MB");
        assert_eq!(path, final_path);
    } else {
        panic!("FolderReceived variant beklendi");
    }
}

#[test]
fn folder_accept_prompt_message_format() {
    // RFC-0005 PR-F: `FolderPromptSummary` core'dan UI'a geçen kontrat.
    // `connection.rs::build_folder_prompt_summary` Introduction'daki bundle
    // marker'dan üretir; UI adapter `prompt.folder_accept.body` template'ini
    // `[root_name, count, human_size]` ile interpolate eder.
    //
    // Bu test sadece struct field'larının taşıdığı değerleri sabitler;
    // rendering (`format_payload_lines`) i18n module-private olduğu için
    // tests'ten çağrılamaz, manuel smoke ile doğrulanır.
    let summary = FolderPromptSummary {
        root_name: "Tatil 2025".to_string(),
        entry_count: 42,
        total_size: 12_345_678,
    };
    assert_eq!(summary.root_name, "Tatil 2025");
    assert_eq!(summary.entry_count, 42);
    assert_eq!(summary.total_size, 12_345_678);
    // root_name boş peer-attack'a karşı sender-side
    // `folder::sanitize::sanitize_root_name` validates; bu kontrat yine de
    // empty olmaması beklenen sender semantiği.
    assert!(!summary.root_name.is_empty());
}

#[test]
fn all_supported_includes_folder_stream_v1() {
    // RFC-0005 PR-F: capability gate. Bu assertion `capabilities.rs`'teki
    // `all_supported_only_has_implemented_features` testinin defensive
    // duplicate'i — integration test seviyesinde de bit'in aktif olduğunu
    // sabitler. PR-F öncesi bu test panic ederdi.
    assert_ne!(features::ALL_SUPPORTED & features::FOLDER_STREAM_V1, 0);
    assert_eq!(
        features::ALL_SUPPORTED,
        features::CHUNK_HMAC_V1 | features::RESUME_V1 | features::FOLDER_STREAM_V1
    );
}
