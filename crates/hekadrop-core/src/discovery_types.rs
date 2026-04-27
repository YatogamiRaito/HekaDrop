//! Discovery sonuçlarının POD tipleri.
//!
//! RFC-0001 §5 Adım 5c — `DiscoveredDevice` core'a taşındı; sender bunu
//! parametre olarak alıyor (kendi `mdns-sd` daemon'una bağlı değil). mDNS
//! resolve fonksiyonları (`scan`, `parse`) app crate'inde `discovery.rs`
//! içinde kalır — `mdns_sd` crate'i app-only.

use std::net::IpAddr;

/// Tek bir keşfedilmiş Quick Share peer'in özet bilgisi.
///
/// Sender flow caller'dan bu yapıyı alır; kendi başına mDNS taraması
/// yapmaz (taramayı app crate'i tetikler ve sonucu sender'a geçirir).
#[derive(Debug, Clone)]
pub struct DiscoveredDevice {
    pub name: String,
    pub addr: IpAddr,
    pub port: u16,
    pub device_type: u8,
    pub fullname: String,
}

impl DiscoveredDevice {
    pub fn kind_label(&self) -> &'static str {
        match self.device_type {
            1 => "📱 Telefon",
            2 => "📱 Tablet",
            3 => "💻 Bilgisayar",
            _ => "❓ Bilinmeyen",
        }
    }
}
