//! mDNS tabanlı Quick Share cihaz keşfi.
//!
//! Karşı tarafın keşfedilebilir olması için Android'de Quick Share görünürlüğünün
//! "Herkes" (Everyone) ayarlı olması gerekir. Aksi halde BLE discovery şart —
//! bu modül yalnız mDNS/WLAN üzerinden çalışır (BLE ileri bir iterasyonda).

use crate::config;
use anyhow::Result;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use mdns_sd::{ServiceDaemon, ServiceEvent};
use std::net::IpAddr;
use std::time::Duration;
use tracing::debug;

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

/// Belirtilen süre boyunca mDNS tarar, bulunan tüm Quick Share cihazlarını döner.
/// Kendi yayın yaptığımız servisi (aynı hostname + port) filtreler.
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
        .and_then(|r| r.ok());

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

fn parse(info: &mdns_sd::ServiceInfo) -> Option<DiscoveredDevice> {
    let addr: IpAddr = info
        .get_addresses()
        .iter()
        .find(|a| a.is_ipv4())
        .copied()?;
    let port = info.get_port();

    let txt = info.get_properties();
    let n_b64 = txt.get("n").and_then(|p| p.val_str().into())?;
    let endpoint_info = URL_SAFE_NO_PAD.decode(n_b64).ok()?;

    if endpoint_info.len() < 18 {
        return None;
    }
    let bitmap = endpoint_info[0];
    let device_type = (bitmap >> 1) & 0x07;
    let name_len = endpoint_info[17] as usize;
    if endpoint_info.len() < 18 + name_len {
        return None;
    }
    let name = String::from_utf8(endpoint_info[18..18 + name_len].to_vec()).ok()?;

    Some(DiscoveredDevice {
        name,
        addr,
        port,
        device_type,
        fullname: info.get_fullname().to_string(),
    })
}
