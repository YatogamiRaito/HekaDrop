//! `HekaDrop` network adapter — mDNS discovery + peer browse.
//!
//! Bu crate, Quick Share'in keşif katmanı için tek noktadır. Domain tipleri
//! (`DiscoveredDevice` vb.) `hekadrop-core::discovery_types` içindedir; bu
//! crate yalnızca network I/O yapan adapter'ları barındırır. Bağımlılık
//! ağacında kenar yönü tek başınadır: `hekadrop-net → hekadrop-core`.
//!
//! RFC-0001 §5 Adım 6 ile çıkarıldı; `mdns-sd` bağımlılığı core'dan buraya
//! taşınarak core'un dependency footprint'i küçültüldü.

// Scope-limited enforce: pedantic umbrella altındaki `missing_errors_doc` ve
// `missing_panics_doc` yalnız `hekadrop-net` public discovery/advertising
// surface için warn olarak aktif. PR #171 + #172 (`hekadrop-core`) pattern'inin
// ufak kardeşi — küçük adapter crate'in public Result-döndüren fn'leri
// (`scan` / `advertise`) için hata kontratı dokümante ediliyor. App/cli/proto
// hâlâ kapsam dışı. CI `-D warnings` ile birlikte fiili enforce sağlar.
// CLAUDE.md I-2: crate-level `#![warn]` `#![allow]` yasağına girmez.
#![warn(clippy::missing_errors_doc, clippy::missing_panics_doc)]

pub mod discovery;
pub mod mdns;
