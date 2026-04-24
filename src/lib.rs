//! HekaDrop library surface — yalnız benchmarklar ve harici entegrasyon testleri
//! için public re-export katmanı.
//!
//! Binary `src/main.rs` bu lib'e bağımlı değildir; modül ağacı ikisinde de
//! bağımsızca derlenir (Cargo lib+bin hibrit projeyi bu şekilde ele alır).
//! Buradaki amaç `benches/crypto.rs` ve `tests/*.rs` gibi harici consumer'lara
//! dar bir yüzey (crypto + file_size_guard + UKEY2 downgrade validator
//! + H#4 privacy controls için settings) açmaktır.

#![allow(dead_code)]

pub mod crypto;
pub mod file_size_guard;

pub mod config;
pub mod log_redact;
pub mod platform;
pub mod settings;

mod error;
mod frame;

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

pub mod secure;
mod ukey2;

pub use ukey2::{validate_server_init, DerivedKeys};
