//! Discovery sonuçlarının POD tipleri.
//!
//! RFC-0001 §5 Adım 5c — `DiscoveredDevice` core'a taşındı; sender bunu
//! parametre olarak alıyor (kendi `mdns-sd` daemon'una bağlı değil). mDNS
//! resolve fonksiyonları (`scan`, `parse`) app crate'inde `discovery.rs`
//! içinde kalır — `mdns_sd` crate'i app-only.

use std::net::IpAddr;

/// Quick Share peer device kategorisi (TXT record `device_type` byte'ından).
/// Display string'leri caller (UI/CLI) tarafında i18n + emoji ile çözülür —
/// core UI/locale-agnostic kalır. PR #93 review (Copilot): `kind_label()` Türkçe
/// + emoji string'leri core'dan çıkartıldı.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceKind {
    Phone,
    Tablet,
    Computer,
    Unknown,
}

impl DeviceKind {
    #[must_use]
    pub fn from_byte(b: u8) -> Self {
        match b {
            1 => Self::Phone,
            2 => Self::Tablet,
            3 => Self::Computer,
            _ => Self::Unknown,
        }
    }
}

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
    /// `true` ise peer mDNS TXT record'unda `ext=1` flag'i göndermiş —
    /// `HekaDrop` extension protocol (capabilities envelope, chunk-HMAC,
    /// resume, folder) destekli. `false` (eski Quick Share peer):
    /// `HekaDropFrame` yollanmamalı; legacy mode kullanılır.
    ///
    /// RFC-0003 §3.3 peer-detection signal. Eski Quick Share peer'larında
    /// `ext` alanı yok → parser default `false` set eder.
    pub extension_supported: bool,
}

impl DiscoveredDevice {
    #[must_use]
    pub fn kind(&self) -> DeviceKind {
        DeviceKind::from_byte(self.device_type)
    }
}
