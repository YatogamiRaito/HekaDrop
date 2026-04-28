//! `HekaDrop` core protocol engine — UKEY2 handshake, kripto primitive'leri,
//! frame codec ve guard'lar. (Payload assembler RFC-0001 Adım 4'te taşınacak.)
//!
//! RFC-0001 §5 Adım 3 ile `hekadrop-app`'tan ayrıştırıldı. Hedef: protocol
//! engine'i UI/global-state'ten arındırarak 3rd party consumer'lara (CLI,
//! daemon, Android router, FFI) `tao`/`wry`/`tray-icon` zinciri olmadan
//! sunmak. RFC §1 M1.
//!
//! # Public surface — STABILITE GARANTİSİ YOK (v1.0.0'a kadar)
//!
//! Bu crate `publish = false`; semver lock'u RFC-0001 Adım 8 (workspace
//! refactor kapanışı) sonunda kurulur. O zamana dek public API breaking
//! değişebilir; her değişiklik CHANGELOG `### Changed` altına not düşer.
//!
//! # Test profili
//!
//! Inline `#[cfg(test)] mod tests` blokları için workspace lint set'inden
//! relax — `lib.rs` `#![cfg_attr(test, allow(...))]`. Production lint
//! disiplini aynen workspace inheritance'tan gelir.

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

pub mod capabilities;
pub mod chunk_hmac;
pub mod config;
pub mod crypto;
pub mod error;
pub mod file_size_guard;
pub mod frame;
pub mod identity;
pub mod log_redact;
// Capabilities exchange runtime helper; `connection` ve `sender` zaten tokio
// bağımlısı olduğundan core'a yeni dep gelmiyor. State machine entegrasyonu
// peer-detection logic ile birlikte ayrı PR'da gelecek.
pub mod negotiation;
pub mod payload;
pub mod secure;
pub mod settings;
pub mod stats;
pub mod ui_port;
pub mod ukey2;

// RFC-0001 §5 Adım 5c — `connection`, `sender`, `server`, `state`,
// `discovery_types` core'a taşındı. Bu modüller `crate::location::*`,
// `crate::sharing::*` çağrı kuyruğunu (in-tree) korumak için protobuf
// bindings'i root-level re-export ediyoruz; aynı pattern app shim'inde
// de var (lib.rs / main.rs).
pub use hekadrop_proto::{location, securegcm, securemessage, sharing};

pub mod connection;
pub mod discovery_types;
pub mod sender;
pub mod server;
pub mod state;

// Fuzz harness (`crates/hekadrop-app/fuzz/fuzz_targets/fuzz_ukey2_handshake_init.rs`)
// ve test'ler eski lib.rs surface üzerinden bu sembolleri root-level alıyordu;
// shim app tarafında devam ettirir ama core de kendi root pub re-export'larını
// belgelemek için aşağıdakileri sabitler.
pub use ukey2::{process_client_init, validate_server_init, DerivedKeys};
