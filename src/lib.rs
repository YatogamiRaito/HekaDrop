//! HekaDrop library surface — yalnız benchmarklar ve harici entegrasyon testleri
//! için public re-export katmanı.
//!
//! Binary `src/main.rs` bu lib'e bağımlı değildir; modül ağacı ikisinde de
//! bağımsızca derlenir (Cargo lib+bin hibrit projeyi bu şekilde ele alır).
//! Buradaki amaç `benches/crypto.rs` ve `tests/*.rs` gibi harici consumer'lara
//! dar bir yüzey (crypto + UKEY2 downgrade validator) açmaktır.

// Lib crate yalnız dar bir yüzey re-export eder; modüllerin geri kalan öğeleri
// `bin` tarafında kullanılıyor. Lib-only build'de onlar için dead_code uyarısı
// çıkar — crate seviyesinde sustur.
#![allow(dead_code)]

pub mod crypto;

// UKEY2 validator'ına entegrasyon testlerinden erişim için gerekli minimum
// modül ağacı. Bunlar `ukey2::validate_server_init`'in derlenmesi için şart
// (use crate::{frame, crypto, securegcm, securemessage}). `pub` değil — sadece
// re-export ettiğimiz sembolleri dışa açıyoruz.
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
mod securemessage {
    include!(concat!(env!("OUT_DIR"), "/securemessage.rs"));
}

mod ukey2;

pub use ukey2::validate_server_init;
