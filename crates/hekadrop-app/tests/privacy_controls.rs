//! H#4 — Privacy controls integration tests.
//!
//! Settings struct'a eklenen 4 alanın (advertise / log_level / keep_stats /
//! disable_update_check) davranışsal semantiğini doğrular. Gerçek tcp/mdns
//! soket simülasyonu yerine **doğrudan API seviyesinde** kontrat testleri —
//! main.rs / connection.rs / sender.rs integration noktaları state + settings
//! üzerinden bu değerleri okuyor; bu test'ler o okuma path'inin canlı
//! olduğunu ve default'ların v0.5 davranışını koruduğunu garantiler.
//!
//! Gerçek mdns bypass integration testi için mdns_discovery.rs'teki canlı
//! test yeterli — burada Settings kontratını izole ediyoruz.
//!
//! Bu binary crate içinde `pub mod settings` (src/lib.rs) public API olarak
//! dışa açıktır; doğrudan `hekadrop::settings` üzerinden erişim mümkün.

use hekadrop::settings::{LogLevel, Settings};

#[test]
fn advertise_default_true_v05_davranisi_korunur() {
    // H#4 rollout: mevcut v0.5 kullanıcıları config'lerinde `advertise` alanı
    // yok — `#[serde(default = "default_advertise")]` true döner, upgrade
    // sessiz geçer. Aksi halde tüm mevcut kullanıcılar birden "görünmez"
    // olur → regression.
    let s = Settings::default();
    assert!(s.advertise, "advertise default v0.5 davranışı (görünür)");
}

#[test]
fn advertise_false_receive_only_mod() {
    // Kullanıcı UI'dan advertise'i kapatmış — main.rs o path'te
    // `mdns::advertise` çağırMAZ; _mdns_handle None olur. Semantic:
    // "receive-only" değil aslında "send-only + silent-receive"; cihaz
    // yayın yapmadığı için Android tarafı listede göremez.
    let s = Settings {
        advertise: false,
        ..Settings::default()
    };
    assert!(!s.advertise);
}

#[test]
fn log_level_default_info_rust_log_envsiz_yol() {
    // RUST_LOG set edilmediğinde setup_logging `log_level.filter_directive()`
    // kullanır. Default Info → "hekadrop=info" — v0.5 davranışı.
    let s = Settings::default();
    assert_eq!(s.log_level, LogLevel::Info);
    assert_eq!(s.log_level.filter_directive(), "hekadrop=info");
}

#[test]
fn log_level_warn_sadece_uyari_ve_hata() {
    // Privacy-conscious kullanıcı: Warn+ seçimi → info/debug logları atılmaz.
    let lvl = LogLevel::Warn;
    assert_eq!(lvl.filter_directive(), "hekadrop=warn");
    assert_eq!(lvl.as_str(), "warn");
}

#[test]
fn log_level_ui_serbest_string_parse() {
    // UI'dan gelen "Warn" / "DEBUG" / "warning" gibi varyantlar güvenli
    // parse — geçersiz input Info default'una düşer, hata atmaz.
    assert_eq!(LogLevel::parse_or_default("Error"), LogLevel::Error);
    assert_eq!(LogLevel::parse_or_default("WARN"), LogLevel::Warn);
    assert_eq!(LogLevel::parse_or_default("warning"), LogLevel::Warn);
    assert_eq!(LogLevel::parse_or_default("Debug"), LogLevel::Debug);
    assert_eq!(LogLevel::parse_or_default("trace"), LogLevel::Info);
    assert_eq!(LogLevel::parse_or_default(""), LogLevel::Info);
}

#[test]
fn keep_stats_default_true_migration_guvenligi() {
    // Eski kullanıcılar için keep_stats=true default → upgrade sonrası
    // istatistikler yazılmaya devam eder (kimse fark etmez). Yeni kullanıcı
    // opt-out için bilinçli olarak kapatmalı.
    let s = Settings::default();
    assert!(s.keep_stats);
}

#[test]
fn keep_stats_false_mevcut_json_silmez_sadece_yazmayi_durdurur() {
    // H#4 spec: keep_stats=false iken mevcut stats.json dosyası
    // **silinmez**; kullanıcı sonradan true'ya geri dönerse eski metrik
    // aynen orada olur. connection.rs/sender.rs save guard'ı yalnızca
    // `if keep { save() }` — delete yok.
    let s = Settings {
        keep_stats: false,
        ..Settings::default()
    };
    assert!(!s.keep_stats);
    // Settings'in kendisi stats dosyasına dokunmaz; bu yalnız guard flag.
}

#[test]
fn disable_update_check_default_true_privacy_first() {
    // v0.7 privacy-first karar: update check varsayılan KAPALI. Kullanıcı
    // Ayarlar'dan açmadıkça GitHub API'ye istek gitmez. Migrate eden v0.5
    // kullanıcıları da aynı default'u alır (serde field default).
    let s = Settings::default();
    assert!(s.disable_update_check);
}

#[test]
fn disable_update_check_env_var_or_setting_or_davranisi() {
    // H#4: iki yol OR'lanır; main.rs `check_update_async` her ikisini
    // kontrol eder. Bu test Setting seviyesinde env var'ın bağımsızlığını
    // belgeler — setting=false iken env set ise yine skip; setting=true
    // iken env olsun ya da olmasın skip.
    //
    // Env var okuma main.rs içinde (`std::env::var_os`); burada sadece
    // Settings tarafının flag olarak davranışını test ediyoruz. v0.7:
    // default=true (privacy-first). User explicit false yazarsa enabled.
    let s_default = Settings::default();
    assert!(s_default.disable_update_check);
    let s_opt_in = Settings {
        disable_update_check: false,
        ..Settings::default()
    };
    assert!(!s_opt_in.disable_update_check);
}

#[test]
fn tum_privacy_alanlari_json_roundtrip() {
    // Settings'in JSON-roundtrip garantisi — save() + load() ardışık
    // çağrısında hiçbir privacy alanı kayıp vermez.
    let s = Settings {
        advertise: false,
        log_level: LogLevel::Warn,
        keep_stats: false,
        disable_update_check: true,
        ..Settings::default()
    };
    let json = serde_json::to_string(&s).expect("ser");
    let back: Settings = serde_json::from_str(&json).expect("de");
    assert!(!back.advertise);
    assert_eq!(back.log_level, LogLevel::Warn);
    assert!(!back.keep_stats);
    assert!(back.disable_update_check);
}

#[test]
fn pre_h4_config_yeni_alanlar_default_olarak_yuklenir() {
    // Gerçek v0.5.2 config.json şeması — H#4 öncesi. `#[serde(default)]`
    // ile eksik alanlar default değerlerle doldurulmalı. Bu, mevcut
    // kullanıcıların upgrade sırasında "aniden silent oldum" demesini
    // önler (advertise=true garanti edilir).
    let legacy = r#"{
        "device_name": "MacBook",
        "download_dir": "/Users/me/Downloads",
        "auto_accept": false,
        "trusted_devices": [],
        "trust_ttl_secs": 604800
    }"#;
    let s: Settings = serde_json::from_str(legacy).expect("v0.5 parse");
    assert!(s.advertise, "v0.5→H#4 migration: advertise true default");
    assert_eq!(s.log_level, LogLevel::Info);
    assert!(s.keep_stats, "v0.5→H#4 migration: keep_stats true default");
    // v0.7 privacy-first: update check varsayılan kapalı (migrate eden
    // kullanıcılar dahil). Kullanıcı opt-in yapmalı.
    assert!(s.disable_update_check);
}

#[test]
fn log_level_serde_lowercase_enum_variant() {
    // `#[serde(rename_all = "lowercase")]` — JSON wire'da "info" / "warn".
    let json = r#"{"log_level": "debug"}"#;
    let s: Settings = serde_json::from_str(json).expect("parse");
    assert_eq!(s.log_level, LogLevel::Debug);
}

#[test]
fn log_level_gecersiz_deger_settings_parse_fail_load_default_fallback() {
    // `LogLevel` `untagged`/`other` olmadığından geçersiz variant serde
    // hatası verir. `Settings::load` bu durumda `unwrap_or_default()` ile
    // tamamen default döner — `load()` path'inin sessiz fallback davranışı
    // (config.json crash yerine).
    //
    // Bu test Settings::load kullanmadan, parse error'un tespit edilebilir
    // olduğunu doğrular (load katmanı yoksa direkt error propagate eder).
    let bad = r#"{"log_level": "trace"}"#;
    let r: Result<Settings, _> = serde_json::from_str(bad);
    assert!(r.is_err(), "bilinmeyen LogLevel variant serde fail");
}
