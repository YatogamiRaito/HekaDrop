//! `HekaDrop` network adapter — mDNS discovery + peer browse.
//!
//! Bu crate, Quick Share'in keşif katmanı için tek noktadır. Domain tipleri
//! (`DiscoveredDevice` vb.) `hekadrop-core::discovery_types` içindedir; bu
//! crate yalnızca network I/O yapan adapter'ları barındırır. Bağımlılık
//! ağacında kenar yönü tek başınadır: `hekadrop-net → hekadrop-core`.
//!
//! RFC-0001 §5 Adım 6 ile çıkarıldı; `mdns-sd` bağımlılığı core'dan buraya
//! taşınarak core'un dependency footprint'i küçültüldü.

// Scope-limited enforce: pedantic umbrella altındaki `missing_errors_doc`,
// `missing_panics_doc` ve `missing_docs_in_private_items` yalnız
// `hekadrop-net` için warn olarak aktif. PR #171 + #172 (`hekadrop-core`)
// public-doc pattern'inin ufak kardeşi (`missing_errors_doc` /
// `missing_panics_doc`); `missing_docs_in_private_items` ise core crate'in
// internal-doc sweep'inin (`chore/lint-missing-docs-private-core`) net
// karşılığı — küçük adapter crate'in 3 private item'ı (`parse` fn +
// `MdnsHandle.daemon` + `MdnsHandle.fullname`) için 1-3 satır intent doc.
// App/cli/proto hâlâ kapsam dışı. CI `-D warnings` ile birlikte fiili
// enforce sağlar. CLAUDE.md I-2: crate-level `#![warn]` `#![allow]` yasağına
// girmez.
#![warn(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::missing_docs_in_private_items
)]

pub mod discovery;
pub mod mdns;
