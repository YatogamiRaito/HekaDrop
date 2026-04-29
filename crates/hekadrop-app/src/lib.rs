//! `HekaDrop` library surface — yalnız benchmarklar ve harici entegrasyon testleri
//! için public re-export katmanı.
//!
//! Binary `src/main.rs` bu lib'e bağımlı değildir; modül ağacı ikisinde de
//! bağımsızca derlenir (Cargo lib+bin hibrit projeyi bu şekilde ele alır).
//! Buradaki amaç `benches/crypto.rs` ve `tests/*.rs` gibi harici consumer'lara
//! dar bir yüzey (crypto + `file_size_guard` + UKEY2 downgrade validator
//! + H#4 privacy controls için settings) açmaktır.

#![allow(dead_code)]
// Test profili (lib unit tests + inline `#[cfg(test)] mod tests`): production
// için ship-blocker olan lint'ler test idiomatik kullanımı engellemesin.
// Integration test'ler (`tests/*.rs`) ayrı crate olduğu için bu attribute
// onlara işlemez — orada her dosya kendi `#![allow]`'unu deklare ediyor.
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
        clippy::cast_possible_wrap,
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

// RFC-0001 §5 — workspace refactor implementation tamamlandı (Adım 1-8):
//   1. Cargo workspace iskele (#85)
//   2. hekadrop-proto crate (#86)
//   3. hekadrop-core pure-crypto core iskele (#89)
//   4. identity/stats/settings/payload core'a (#90)
//   5a. AppState plain struct (#91)
//   5b. UiPort trait + UiNotification (#92)
//   5c. state/connection/sender/server core'a (#93)
//   6. hekadrop-net crate (mdns/discovery adapter) (bu PR)
//   7. hekadrop-cli stub (bu PR)
//   8. lib.rs shim'in kalıcı dokümantasyonu (bu blok)
//
// Bu re-export'lar `tests/*.rs`, `benches/*.rs` ve fuzz harness'larının
// `hekadrop::xxx` formuyla core sembollerine erişebilmesi için kalır
// (binary `src/main.rs` direkt `hekadrop_core::xxx` kullanır; lib bağımsız
// derlenir). Yeni core sembolü eklendiğinde tek mecburi update buradadır.
pub use hekadrop_core::{
    capabilities, config, connection, crypto, discovery_types, error, file_size_guard, frame,
    identity, log_redact, payload, resume, secure, sender, server, settings, stats, ui_port, ukey2,
};

// RFC-0001 §5 Adım 2: protobuf bindings `hekadrop-proto` crate'inden
// re-export ediliyor. `crate::securegcm::...`, `crate::location::...`,
// `crate::sharing::...`, `crate::securemessage::...` çağrıları kod tabanı
// boyunca korunur (yüzlerce import noktası dokunulmaz).
pub use hekadrop_proto::{location, securegcm, securemessage, sharing};

// `tests/ukey2_handshake.rs` + `tests/ukey2_downgrade.rs` ve fuzz harness
// (`fuzz_ukey2_handshake_init`) bu sembolleri root-level `hekadrop::xxx` ile
// alıyordu — Adım 3 öncesi yüzeyi korumak için aynı seviyede yeniden export.
pub use hekadrop_core::{process_client_init, validate_server_init, DerivedKeys};

// `platform` modülü uygulamaya özgüdür (Win32 / macOS Cocoa / Linux GTK
// shim'leri); core'a sızdırılmaz, tests/benches da bu modüle dokunmaz.
// `pub(crate)` ile lib surface dışına çıkarıldı — PR #107 review (Copilot)
// `pub mod` + iç items `pub(crate)` tutarsızlığını yakaladı.
pub(crate) mod platform;
