//! `HekaDrop`'un Quick Share / Nearby Connections protobuf bindings'i.
//!
//! Tüm `pub mod` blokları `build.rs` üzerinden `prost-build` tarafından
//! `OUT_DIR`'a üretilen modülleri include eder. Bu crate runtime mantığı
//! barındırmaz — sadece wire-format tipleri ve `Default`/`Clone` türevleridir.
//!
//! Proto kaynakları upstream Google/Nearby Connections SDK reverse-engineering
//! ürünüdür; bkz. `proto/` dizini ve `docs/protocol/README.md`.
//!
//! # Lint disiplini
//!
//! Bu crate **el yazımı kod barındırmaz** — sadece module declaration'ları ve
//! `include!()` macro'ları. Bu nedenle lint allow'ları **crate-level değil,
//! her generated module'a `#[allow]` outer attribute olarak** uygulanır:
//!
//! - El yazımı yardımcı (helper function, type alias, vb.) gelecekte
//!   eklenirse Rust disiplini altında kalır (allow gevşekliği bulaşmaz).
//! - Allow set'i sadece prost'un ürettiği kodun gerektirdiği lint'ler:
//!   `non_snake_case`/`non_camel_case_types` (proto field/enum convention),
//!   `clippy::all` (prost-generated derive'lar), `unused_qualifications`
//!   (prost fully-qualified path kullanır), `rustdoc::invalid_html_tags`
//!   (proto comment'lardaki `<...>` benzeri token'lar), `dead_code`
//!   (test'lerde kullanılmayan tipler için), `clippy::must_use_candidate`
//!   (prost-generated `as_str_name` / `from_str_name` enum helper'ları —
//!   workspace-wide enforce'a dahil edildi, generated kod düzeltilemez).
//!
//! Daha iyi olası iyileştirme (yapılmadı, GH issue'da takip edilmeli):
//! `prost-build` config'inde `.message_attribute()` ile generated kod'a
//! `#[allow(...)]` inject etmek. O zaman bu wrapper bile gerekmezdi. Şimdilik
//! sade çözüm yeterli; v0.8 implementation fazında değerlendirilir.

// PROTO: prost-üretilmiş modül; el yazımı kontrol dışı. Generated kod proto
// field/enum convention'larını (snake_case ihlali, doc_markdown vb.) koruyamaz.
// Module-level `#[allow]` CLAUDE.md I-2 istisnası (sadece generated kod
// include'u için sanctioned). `#[expect]` denendi → her generated modül her
// lint'i tetiklemediği için unfulfilled hataları çıktı; allow burada doğru
// disiplin.
#[allow(
    clippy::all,
    clippy::doc_markdown,
    clippy::must_use_candidate,
    non_snake_case,
    non_camel_case_types,
    dead_code,
    unused_qualifications,
    rustdoc::invalid_html_tags,
    rustdoc::broken_intra_doc_links
)]
pub mod securegcm {
    include!(concat!(env!("OUT_DIR"), "/securegcm.rs"));
}

// PROTO: prost-üretilmiş modül; el yazımı kontrol dışı. Generated kod proto
// field/enum convention'larını (snake_case ihlali, doc_markdown vb.) koruyamaz.
// Module-level `#[allow]` CLAUDE.md I-2 istisnası (sadece generated kod
// include'u için sanctioned). `#[expect]` denendi → her generated modül her
// lint'i tetiklemediği için unfulfilled hataları çıktı; allow burada doğru
// disiplin.
#[allow(
    clippy::all,
    clippy::doc_markdown,
    clippy::must_use_candidate,
    non_snake_case,
    non_camel_case_types,
    dead_code,
    unused_qualifications,
    rustdoc::invalid_html_tags,
    rustdoc::broken_intra_doc_links
)]
pub mod securemessage {
    include!(concat!(env!("OUT_DIR"), "/securemessage.rs"));
}

// PROTO: prost-üretilmiş modül; el yazımı kontrol dışı. Generated kod proto
// field/enum convention'larını (snake_case ihlali, doc_markdown vb.) koruyamaz.
// Module-level `#[allow]` CLAUDE.md I-2 istisnası (sadece generated kod
// include'u için sanctioned). `#[expect]` denendi → her generated modül her
// lint'i tetiklemediği için unfulfilled hataları çıktı; allow burada doğru
// disiplin.
#[allow(
    clippy::all,
    clippy::doc_markdown,
    clippy::must_use_candidate,
    non_snake_case,
    non_camel_case_types,
    dead_code,
    unused_qualifications,
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

// PROTO: prost-üretilmiş modül; el yazımı kontrol dışı. Generated kod proto
// field/enum convention'larını (snake_case ihlali, doc_markdown vb.) koruyamaz.
// Module-level `#[allow]` CLAUDE.md I-2 istisnası (sadece generated kod
// include'u için sanctioned). `#[expect]` denendi → her generated modül her
// lint'i tetiklemediği için unfulfilled hataları çıktı; allow burada doğru
// disiplin.
#[allow(
    clippy::all,
    clippy::doc_markdown,
    clippy::must_use_candidate,
    non_snake_case,
    non_camel_case_types,
    dead_code,
    unused_qualifications,
    rustdoc::invalid_html_tags,
    rustdoc::broken_intra_doc_links
)]
pub mod sharing {
    pub mod nearby {
        include!(concat!(env!("OUT_DIR"), "/sharing.nearby.rs"));
    }
}

/// HekaDrop-only protocol extension envelope (RFC-0003 §3.2).
///
/// Wire layout: 4-byte big-endian magic (`0xA5DEB201`) — protobuf-DIŞINDA,
/// raw prefix — ardından `HekaDropFrame` protobuf encoding'i. Magic
/// dispatcher seviyesinde strip edilir (`hekadrop-core::frame`).
///
/// Slot tahsisi: capabilities=10, `chunk_tag=11`, `resume_hint=12`,
/// `resume_reject=13`, `folder_mft=14`. 1..9 ve 15..63 reserved.
///
/// Wire-byte-exact spec: `docs/protocol/capabilities.md`.
// PROTO: prost-üretilmiş modül; el yazımı kontrol dışı. Generated kod proto
// field/enum convention'larını (snake_case ihlali, doc_markdown vb.) koruyamaz.
// Module-level `#[allow]` CLAUDE.md I-2 istisnası (sadece generated kod
// include'u için sanctioned). `#[expect]` denendi → her generated modül her
// lint'i tetiklemediği için unfulfilled hataları çıktı; allow burada doğru
// disiplin.
#[allow(
    clippy::all,
    clippy::doc_markdown,
    clippy::must_use_candidate,
    non_snake_case,
    non_camel_case_types,
    dead_code,
    unused_qualifications,
    rustdoc::invalid_html_tags,
    rustdoc::broken_intra_doc_links
)]
pub mod hekadrop_ext {
    include!(concat!(env!("OUT_DIR"), "/hekadrop.ext.rs"));
}
