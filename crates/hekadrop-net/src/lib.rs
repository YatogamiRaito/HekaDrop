//! HekaDrop network adapter — mDNS discovery + peer browse.
//!
//! Bu crate, Quick Share'in keşif katmanı için tek noktadır. Domain tipleri
//! (`DiscoveredDevice` vb.) `hekadrop-core::discovery_types` içindedir; bu
//! crate yalnızca network I/O yapan adapter'ları barındırır. Bağımlılık
//! ağacında kenar yönü tek başınadır: `hekadrop-net → hekadrop-core`.
//!
//! RFC-0001 §5 Adım 6 ile çıkarıldı; `mdns-sd` bağımlılığı core'dan buraya
//! taşınarak core'un dependency footprint'i küçültüldü.

pub mod discovery;
pub mod mdns;
