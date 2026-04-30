use anyhow::Result;
use hekadrop_core::config;
use mdns_sd::{ServiceDaemon, ServiceInfo};
use std::net::IpAddr;
use tracing::{info, warn};

pub struct MdnsHandle {
    daemon: ServiceDaemon,
    fullname: String,
}

impl Drop for MdnsHandle {
    fn drop(&mut self) {
        let _ = self.daemon.unregister(&self.fullname);
    }
}

/// mDNS yayınını başlatır.
///
/// `None` döner: ağ arayüzü yoksa — bu durumda uygulama UI olarak çalışmaya
/// devam eder (Ayarlar/Geçmiş görüntülenebilir), sadece yeni cihazlar
/// keşfedilemez. Bu davranış kasıtlı: ağ kablosu çıkıkken uygulamayı açıp
/// kapatmak gerekmesin.
///
/// # Errors
///
/// Returns `Err` if:
/// - `if_addrs::get_if_addrs()` ağ arayüzü listesi alamadı (OS hatası)
/// - `ServiceInfo::new` instance/host/property metadata'sını doğrulayamadı
/// - `ServiceDaemon::new` socket bind / thread spawn başarısız oldu
/// - `daemon.register` mDNS multicast kayıt yayınını gönderemedi
pub fn advertise(device_name: &str, port: u16) -> Result<Option<MdnsHandle>> {
    let service_type = config::service_type();
    let endpoint_id = config::random_endpoint_id();
    let instance = config::instance_name(endpoint_id);
    let endpoint_info_b64 = config::endpoint_info_b64(device_name);

    // Sadece fiziksel/kablosuz arayüzleri yayınla. Docker, libvirt, Tailscale ve
    // benzerleri LAN üzerinden erişilebilir değil; Android phone yanlış IP'yi
    // deneyip başarısız olursa transfer düşer.
    //
    // İki filtre katmanı: (1) OS-seviyeli point-to-point flag (if-addrs 0.15+
    // `is_p2p()`; Windows/macOS/Linux'ta tutarlı olmayan tunel bayrağı),
    // (2) aşağıdaki `skip_prefix` — p2p flag yakalamadığı VPN / köprü / container
    // arayüzleri için isim-prefix denylist'i.
    // Defensive: ikisi belt-and-suspenders; biri kaçırırsa diğeri yakalar.
    let skip_prefix = [
        "docker",
        "br-",
        "veth",
        "virbr",
        "vnet",
        "tailscale",
        "zt",
        "tun",
        "tap",
        "wg",
    ];
    let addrs: Vec<IpAddr> = if_addrs::get_if_addrs()?
        .into_iter()
        .filter(|i| !i.is_loopback())
        .filter(|i| !i.is_p2p())
        .filter(|i| !skip_prefix.iter().any(|p| i.name.starts_with(p)))
        .map(|i| i.ip())
        .filter(std::net::IpAddr::is_ipv4)
        .collect();

    if addrs.is_empty() {
        warn!(
            "mDNS yayını için uygun IPv4 adresi yok (kablo çıkık / sanal arayüzler filtrelendi) — \
             mDNS devre dışı; ağ bağlantısı geldiğinde uygulamayı yeniden başlatın"
        );
        return Ok(None);
    }

    // RFC-0003 §3.3 peer-detection signal:
    //   `ext=1` flag → bu instance HekaDrop extension protocol (capabilities
    //   envelope, chunk-HMAC, resume, folder) destekli. Eski Quick Share
    //   peer'ları bu alanı görmezden gelir (sadece "n" endpoint info'yu
    //   parse ederler). HekaDrop discovery `extension_supported` field'ını
    //   bu flag'in varlığına göre set eder.
    let info = ServiceInfo::new(
        &service_type,
        &instance,
        &format!("{instance}.local."),
        &addrs[..],
        port,
        &[("n", endpoint_info_b64.as_str()), ("ext", "1")][..],
    )?;

    let fullname = info.get_fullname().to_string();

    let daemon = ServiceDaemon::new()?;
    daemon.register(info)?;

    info!(
        "mDNS yayında: type={} instance={} name=\"{}\" endpoint_id={} addrs={:?}",
        service_type,
        instance,
        device_name,
        String::from_utf8_lossy(&endpoint_id),
        addrs,
    );

    Ok(Some(MdnsHandle { daemon, fullname }))
}
