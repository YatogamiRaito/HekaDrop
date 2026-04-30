//! mDNS tabanlı Quick Share cihaz keşfi.
//!
//! Karşı tarafın keşfedilebilir olması için Android'de Quick Share görünürlüğünün
//! "Herkes" (Everyone) ayarlı olması gerekir. Aksi halde BLE discovery şart —
//! bu modül yalnız mDNS/WLAN üzerinden çalışır (BLE ileri bir iterasyonda).

use anyhow::Result;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hekadrop_core::config;
use mdns_sd::{ResolvedService, ServiceDaemon, ServiceEvent};
use std::net::IpAddr;
use std::time::Duration;
use tracing::debug;

// RFC-0001 §5 Adım 5c — `DiscoveredDevice` POD core'a taşındı
// (`hekadrop_core::discovery_types`). App crate'i mDNS scan'i ve
// parse'ı barındırır; sender / UI bu re-export üzerinden tipi alır.
pub use hekadrop_core::discovery_types::DiscoveredDevice;

/// Belirtilen süre boyunca mDNS tarar, bulunan tüm Quick Share cihazlarını döner.
/// Kendi yayın yaptığımız servisi (aynı hostname + port) filtreler.
///
/// # Errors
///
/// Returns `Err` if:
/// - `mdns-sd` `ServiceDaemon` başlatılamadı (socket bind / OS resource hatası)
/// - Browse subscription kurulamadı (daemon kapalı / kanal hatası)
pub async fn scan(duration: Duration, own_port: u16) -> Result<Vec<DiscoveredDevice>> {
    let daemon = ServiceDaemon::new()?;
    let service_type = config::service_type();
    let rx = daemon.browse(&service_type)?;

    let deadline = std::time::Instant::now() + duration;
    let mut devices: Vec<DiscoveredDevice> = Vec::new();

    loop {
        let now = std::time::Instant::now();
        if now >= deadline {
            break;
        }
        let remaining = deadline - now;

        let rx2 = rx.clone();
        let event_opt = tokio::task::spawn_blocking(move || {
            rx2.recv_timeout(remaining.min(Duration::from_millis(500)))
        })
        .await
        .ok()
        .and_then(std::result::Result::ok);

        let Some(event) = event_opt else { continue };

        if let ServiceEvent::ServiceResolved(info) = event {
            // Kendi yayınımız filtrele
            if info.get_port() == own_port {
                continue;
            }
            let Some(dev) = parse(&info) else { continue };
            if !devices.iter().any(|d| d.fullname == dev.fullname) {
                debug!(
                    "keşfedildi: {} ({}:{}) type={}",
                    dev.name, dev.addr, dev.port, dev.device_type
                );
                devices.push(dev);
            }
        }
    }

    daemon.shutdown().ok();
    Ok(devices)
}

fn parse(info: &ResolvedService) -> Option<DiscoveredDevice> {
    // v0.15+ API: get_addresses() artık `&HashSet<ScopedIp>` döner; IPv4 için
    // get_addresses_v4() → `&HashSet<Ipv4Addr>`; .iter() `&Ipv4Addr` verir.
    // Çok adresli (multi-homed) cihazlarda deterministik seçim için `.min()`:
    // HashSet iteration sırası belirsizdir, aynı taramada aynı IP dönsün.
    let addr: IpAddr = info
        .get_addresses_v4()
        .iter()
        .min()
        .map(|ip| IpAddr::V4(*ip))?;
    let port = info.get_port();

    let n_b64 = info.get_property_val_str("n")?;
    let endpoint_info = URL_SAFE_NO_PAD.decode(n_b64).ok()?;

    if endpoint_info.len() < 17 {
        return None;
    }
    let bitmap = endpoint_info[0];
    let device_type = (bitmap >> 1) & 0x07;

    let name = if endpoint_info.len() >= 18 {
        let name_len = endpoint_info[17] as usize;
        if endpoint_info.len() >= 18 + name_len && name_len > 0 {
            String::from_utf8(endpoint_info[18..18 + name_len].to_vec()).ok()
        } else {
            None
        }
    } else {
        None
    }
    .unwrap_or_else(|| {
        info.get_hostname()
            .trim_end_matches('.')
            .trim_end_matches(".local")
            .to_string()
    });

    let extension_supported = parse_extension_flag(info.get_property_val_str("ext"));

    Some(DiscoveredDevice {
        name,
        addr,
        port,
        device_type,
        fullname: info.get_fullname().to_string(),
        extension_supported,
    })
}

/// RFC-0003 §3.3 peer-detection — TXT record'undaki `ext` alanından `HekaDrop`
/// extension destek flag'ini parse et.
///
/// Eski Quick Share peer'larında (Pixel/Samsung/NearDrop/rquickshare) `ext`
/// alanı yoktur → `None` → `false` (legacy mode).
/// `HekaDrop` peer'ları `ext=1` yollar → `Some("1")` → `true`.
/// Beklenmeyen değerler (`"0"`, `"true"`, vb.) → `false` (defensive — yalnız
/// "1" tam pozitif sinyal sayılır).
#[must_use]
pub(crate) fn parse_extension_flag(prop_value: Option<&str>) -> bool {
    prop_value == Some("1")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Eski Quick Share peer (Pixel/Samsung/NearDrop) — `ext` alanı yok.
    #[test]
    fn missing_ext_property_legacy() {
        assert!(!parse_extension_flag(None));
    }

    /// `HekaDrop` peer — `ext=1` spec değeri.
    #[test]
    fn ext_one_signals_extension_support() {
        assert!(parse_extension_flag(Some("1")));
    }

    /// Defensive: "1" dışı hiçbir değer pozitif sinyal sayılmaz.
    /// Saldırgan veya yanlışlıkla farklı flag yollayan peer extension
    /// destekliyor sayılmamalı (false-positive → connection drop riski).
    #[test]
    fn unexpected_values_default_to_legacy() {
        assert!(!parse_extension_flag(Some("0")));
        assert!(!parse_extension_flag(Some("true")));
        assert!(!parse_extension_flag(Some("yes")));
        assert!(!parse_extension_flag(Some("")));
        assert!(!parse_extension_flag(Some(" 1")));
        assert!(!parse_extension_flag(Some("1 ")));
        assert!(!parse_extension_flag(Some("2")));
    }
}
