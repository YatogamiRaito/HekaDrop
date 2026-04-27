//! HekaDrop library surface — yalnız benchmarklar ve harici entegrasyon testleri
//! için public re-export katmanı.
//!
//! Binary `src/main.rs` bu lib'e bağımlı değildir; modül ağacı ikisinde de
//! bağımsızca derlenir (Cargo lib+bin hibrit projeyi bu şekilde ele alır).
//! Buradaki amaç `benches/crypto.rs` ve `tests/*.rs` gibi harici consumer'lara
//! dar bir yüzey (crypto + file_size_guard + UKEY2 downgrade validator
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

pub mod crypto;
pub mod file_size_guard;

pub mod config;
pub mod log_redact;
pub mod platform;
pub mod settings;

mod error;
mod frame;

// RFC-0001 §5 Adım 2: protobuf bindings `hekadrop-proto` crate'inden
// re-export ediliyor. `crate::securegcm::...`, `crate::location::...`,
// `crate::sharing::...`, `crate::securemessage::...` çağrıları kod tabanı
// boyunca korunur (yüzlerce import noktası dokunulmaz). Dual-include
// borcu (lib.rs + main.rs aynı bloku yineliyordu) bu adımla kapandı.
pub use hekadrop_proto::{location, securegcm, securemessage, sharing};

mod ukey2;

pub use ukey2::{validate_server_init, DerivedKeys};

// TODO(fuzz/Q1): `process_client_init` ham bir `&[u8]` alıp `Ukey2Message` +
// `Ukey2ClientInit` decode + validation pipeline'ını çalıştırır — `fuzz/`
// harness'i (`fuzz_ukey2_handshake_init`) tam bu parser'ı hedefler. Lib
// surface'i minimum tutmak için yalnızca fuzz için re-export ediyoruz; üretim
// çağrıları hâlâ crate-içi. Q2'de UKEY2 modülü `hekadrop-core` crate'ine
// ayrıldığında bu export natural olarak `pub` API hâline gelecek.
pub use ukey2::process_client_init;

// `PayloadAssembler` için gerekli. Entegrasyon testleri (örn.
// `tests/payload_corrupt.rs`) ingest API üzerinden chunk senaryolarını
// (overrun / truncation / duplicate id / out-of-order) doğrular.
pub mod payload;

// `SecureCtx` için gerekli. Entegrasyon testleri (örn. `tests/hmac_tag_length.rs`)
// `SecureMessage` protobuf'ını elle kurup `SecureCtx::decrypt`'e veriyor — bu yüzden
// modül + SecureMessage tipi lib-surface'den görünmeli.
pub mod secure;
