//! HekaDrop'un Quick Share / Nearby Connections protobuf bindings'i.
//!
//! Tüm `pub mod` blokları `build.rs` üzerinden `prost-build` tarafından
//! `OUT_DIR`'a üretilen modülleri include eder. Bu crate runtime mantığı
//! barındırmaz — sadece wire-format tipleri ve `Default`/`Clone` türevleridir.
//!
//! Proto kaynakları upstream Google/Nearby Connections SDK reverse-engineering
//! ürünüdür; bkz. `proto/` dizini ve `docs/protocol/README.md`.

// Generated kod prost'tan; clippy + rustdoc + style lint'leri bizim
// kontrolümüzde değil. Eski `hekadrop-app/src/lib.rs`'in proto modüllerine
// uyguladığı tam #![allow] seti burada da uygulanır (Gemini PR-86 yorumu):
// proto field/enum identifier'ları upstream Google convention'ı (camelCase
// ve PascalCase karışımı) ile geliyor; rustdoc'taki HTML benzeri etiketler
// proto comment'larından kaynaklanıyor.
#![allow(clippy::all)]
#![allow(clippy::pedantic)]
#![allow(unused_qualifications)]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(dead_code)]
#![allow(rustdoc::invalid_html_tags)]
#![allow(rustdoc::broken_intra_doc_links)]

/// Google Nearby Connections SecureGCM frame'leri ve UKEY2 handshake mesajları.
pub mod securegcm {
    include!(concat!(env!("OUT_DIR"), "/securegcm.rs"));
}

/// Google Nearby Connections SecureMessage envelope (HMAC + AES-CBC layer).
pub mod securemessage {
    include!(concat!(env!("OUT_DIR"), "/securemessage.rs"));
}

/// Nearby Connections location-based discovery ve transfer frame'leri.
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

/// Quick Share sharing protokol mesajları (Introduction, PayloadTransfer, vs.).
pub mod sharing {
    pub mod nearby {
        include!(concat!(env!("OUT_DIR"), "/sharing.nearby.rs"));
    }
}
