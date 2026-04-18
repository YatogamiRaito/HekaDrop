//! Settings JSON migration / backward compatibility.
//!
//! Şu anki şema: `trusted_devices: Vec<String>`. İlerde muhtemel evolution:
//! - `Vec<TrustedDevice { name, trusted_at, last_seen }>`.
//!
//! Bug-hunter-a ajanının planladığı migration tamamlanırsa, eski format yeni
//! format'a okunabilmeli. Bu dosya senaryoları *şimdiden* listeler; gerçek kod
//! yetişmezse skip'lenir (`#[ignore]` ile işaretlenmiş değil, cevap veren
//! yapı sırasında panic yerine graceful fallback doğrulanır).

use serde::{Deserialize, Serialize};

/// Şu anki public Settings şeması — `src/settings.rs` ile uyumlu.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
struct SettingsV1 {
    #[serde(default)]
    device_name: Option<String>,
    #[serde(default)]
    download_dir: Option<String>,
    #[serde(default)]
    auto_accept: bool,
    #[serde(default)]
    trusted_devices: Vec<String>,
}

/// Gelecekteki V2 şema — bug-hunter-a'nın planı. V1 JSON okunduğunda
/// `trusted_at`/`last_seen` None yazılır.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
enum TrustedDeviceV2 {
    /// Eski formattan gelen: sadece string.
    Legacy(String),
    /// Yeni format: struct.
    Rich {
        name: String,
        #[serde(default)]
        trusted_at: Option<u64>,
        #[serde(default)]
        last_seen: Option<u64>,
    },
}

impl TrustedDeviceV2 {
    fn name(&self) -> &str {
        match self {
            TrustedDeviceV2::Legacy(n) => n,
            TrustedDeviceV2::Rich { name, .. } => name,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
struct SettingsV2 {
    #[serde(default)]
    device_name: Option<String>,
    #[serde(default)]
    download_dir: Option<String>,
    #[serde(default)]
    auto_accept: bool,
    #[serde(default)]
    trusted_devices: Vec<TrustedDeviceV2>,
}

/// Fallback loader: önce V2 olarak dene, olmazsa V1, olmazsa default.
fn load_or_default(json: &str) -> SettingsV2 {
    if let Ok(s2) = serde_json::from_str::<SettingsV2>(json) {
        return s2;
    }
    if let Ok(s1) = serde_json::from_str::<SettingsV1>(json) {
        return SettingsV2 {
            device_name: s1.device_name,
            download_dir: s1.download_dir,
            auto_accept: s1.auto_accept,
            trusted_devices: s1
                .trusted_devices
                .into_iter()
                .map(TrustedDeviceV2::Legacy)
                .collect(),
        };
    }
    SettingsV2::default()
}

#[test]
fn bos_json_default_fallback() {
    let json = "{}";
    let s: SettingsV1 = serde_json::from_str(json).unwrap();
    assert_eq!(s, SettingsV1::default());
}

#[test]
fn malformed_json_default_fallback() {
    let bad = "{not-valid-json}";
    let s = load_or_default(bad);
    assert_eq!(s, SettingsV2::default());
}

#[test]
fn truncated_json_default_fallback() {
    let bad = "{\"device_name\":\"Mac\""; // eksik kapanış
    let s = load_or_default(bad);
    assert_eq!(s, SettingsV2::default());
}

#[test]
fn v1_vec_string_okunabilir() {
    let json = r#"{
        "device_name": "MacBook",
        "download_dir": "/Users/me/Downloads",
        "auto_accept": true,
        "trusted_devices": ["iPhone", "iPad"]
    }"#;
    let s: SettingsV1 = serde_json::from_str(json).expect("V1 parse");
    assert_eq!(s.device_name.as_deref(), Some("MacBook"));
    assert!(s.auto_accept);
    assert_eq!(
        s.trusted_devices,
        vec!["iPhone".to_string(), "iPad".to_string()]
    );
}

/// V1 format load_or_default üzerinden V2'ye migrate edilmeli.
#[test]
fn v1_otomatik_v2_ye_migrate() {
    let json = r#"{
        "device_name": "MacBook",
        "trusted_devices": ["iPhone", "iPad"]
    }"#;
    let s = load_or_default(json);
    assert_eq!(s.device_name.as_deref(), Some("MacBook"));
    assert_eq!(s.trusted_devices.len(), 2);
    assert_eq!(s.trusted_devices[0].name(), "iPhone");
    assert_eq!(s.trusted_devices[1].name(), "iPad");
    // Legacy olarak dekode olmalı
    assert!(matches!(s.trusted_devices[0], TrustedDeviceV2::Legacy(_)));
}

/// V2 format doğrudan parse edilebilmeli (karışık legacy + rich).
#[test]
fn v2_karma_legacy_rich_parse() {
    let json = r#"{
        "trusted_devices": [
            "LegacyName",
            {"name": "NewPhone", "trusted_at": 1700000000, "last_seen": 1700100000}
        ]
    }"#;
    let s = load_or_default(json);
    assert_eq!(s.trusted_devices.len(), 2);
    assert!(matches!(s.trusted_devices[0], TrustedDeviceV2::Legacy(_)));
    assert!(matches!(s.trusted_devices[1], TrustedDeviceV2::Rich { .. }));
    assert_eq!(s.trusted_devices[0].name(), "LegacyName");
    assert_eq!(s.trusted_devices[1].name(), "NewPhone");
}

/// V2 fresh: tüm rich struct'lar.
#[test]
fn v2_fresh_format_rich_only() {
    let json = r#"{
        "trusted_devices": [
            {"name": "A", "trusted_at": 100, "last_seen": 200},
            {"name": "B"}
        ]
    }"#;
    let s = load_or_default(json);
    assert_eq!(s.trusted_devices.len(), 2);
    match &s.trusted_devices[0] {
        TrustedDeviceV2::Rich {
            name,
            trusted_at,
            last_seen,
        } => {
            assert_eq!(name, "A");
            assert_eq!(*trusted_at, Some(100));
            assert_eq!(*last_seen, Some(200));
        }
        _ => panic!("Rich beklenir"),
    }
    // İkincisinde trusted_at/last_seen yoktu → None default
    match &s.trusted_devices[1] {
        TrustedDeviceV2::Rich {
            trusted_at,
            last_seen,
            ..
        } => {
            assert_eq!(*trusted_at, None);
            assert_eq!(*last_seen, None);
        }
        _ => panic!("Rich beklenir"),
    }
}

#[test]
fn bilinmeyen_alanlar_ignored_forward_compat() {
    // Yeni sürüm ek alan ekleyebilir; eski sürüm onu sessizce ignore etmeli
    let json = r#"{
        "device_name": "Mac",
        "future_new_field": 42,
        "trusted_devices": []
    }"#;
    let s: SettingsV1 = serde_json::from_str(json).expect("bilinmeyen alan ignore edilmeli");
    assert_eq!(s.device_name.as_deref(), Some("Mac"));
}

/// `is_trusted` davranışı — isim tabanlı (V1) ve struct tabanlı (V2) akışta aynı.
#[test]
fn is_trusted_hem_v1_hem_v2_de_calisir() {
    let v1 = SettingsV1 {
        trusted_devices: vec!["Alice".into(), "Bob".into()],
        ..Default::default()
    };
    assert!(v1.trusted_devices.iter().any(|n| n == "Alice"));
    assert!(!v1.trusted_devices.iter().any(|n| n == "Carol"));

    let v2 = SettingsV2 {
        trusted_devices: vec![
            TrustedDeviceV2::Legacy("Alice".into()),
            TrustedDeviceV2::Rich {
                name: "Bob".into(),
                trusted_at: None,
                last_seen: None,
            },
        ],
        ..Default::default()
    };
    assert!(v2.trusted_devices.iter().any(|d| d.name() == "Alice"));
    assert!(v2.trusted_devices.iter().any(|d| d.name() == "Bob"));
    assert!(!v2.trusted_devices.iter().any(|d| d.name() == "Carol"));
}

#[test]
fn roundtrip_v1_serialize_deserialize_identical() {
    let s = SettingsV1 {
        device_name: Some("Mac".into()),
        download_dir: None,
        auto_accept: true,
        trusted_devices: vec!["a".into(), "b".into()],
    };
    let json = serde_json::to_string(&s).unwrap();
    let back: SettingsV1 = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

/// Eski JSON'da tip yanlış yazılmışsa (örn. trusted_devices bir obje): fallback.
#[test]
fn trusted_devices_yanlis_tip_fallback_default() {
    let bad = r#"{"trusted_devices": "not-a-list"}"#;
    let s = load_or_default(bad);
    // String'leri listeye koyamadığı için SettingsV1 de V2 de parse edilemez.
    assert_eq!(s, SettingsV2::default());
}
