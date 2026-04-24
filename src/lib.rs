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

// main.rs ile dual-include senkronu — build.rs yeni .proto eklediğinde
// buraya da eklenmeli. Aksi halde lib surface'i sınırlı kalır; test kodu
// protobuf tiplerini doğrudan kurmak isterse derlenmez. Şu an tüm üretilen
// modüller burada expose edilir (main.rs ile birebir eşleşir).
#[allow(
    clippy::all,
    non_snake_case,
    non_camel_case_types,
    dead_code,
    rustdoc::invalid_html_tags,
    rustdoc::broken_intra_doc_links
)]
pub mod location {
    pub mod nearby {
        pub mod connections {
            include!(concat!(env!("OUT_DIR"), "/location.nearby.connections.rs"));
        }
        pub mod proto {
            pub mod sharing {
                include!(concat!(
                    env!("OUT_DIR"),
                    "/location.nearby.proto.sharing.rs"
                ));
            }
        }
    }
}

#[allow(
    clippy::all,
    non_snake_case,
    non_camel_case_types,
    dead_code,
    rustdoc::invalid_html_tags,
    rustdoc::broken_intra_doc_links
)]
pub mod sharing {
    pub mod nearby {
        include!(concat!(env!("OUT_DIR"), "/sharing.nearby.rs"));
    }
}

mod ukey2;

pub use ukey2::{validate_server_init, DerivedKeys};

// `PayloadAssembler` için gerekli. Entegrasyon testleri (örn.
// `tests/payload_corrupt.rs`) ingest API üzerinden chunk senaryolarını
// (overrun / truncation / duplicate id / out-of-order) doğrular.
pub mod payload;

// `SecureCtx` için gerekli. Entegrasyon testleri (örn. `tests/hmac_tag_length.rs`)
// `SecureMessage` protobuf'ını elle kurup `SecureCtx::decrypt`'e veriyor — bu yüzden
// modül + SecureMessage tipi lib-surface'den görünmeli.
pub mod secure;
