use crate::config;
use anyhow::Result;
use mdns_sd::{ServiceDaemon, ServiceInfo};
use std::net::IpAddr;
use tracing::info;

pub struct MdnsHandle {
    daemon: ServiceDaemon,
    fullname: String,
}

impl Drop for MdnsHandle {
    fn drop(&mut self) {
        let _ = self.daemon.unregister(&self.fullname);
    }
}

pub fn advertise(device_name: &str, port: u16) -> Result<MdnsHandle> {
    let service_type = config::service_type();
    let endpoint_id = config::random_endpoint_id();
    let instance = config::instance_name(&endpoint_id);
    let endpoint_info_b64 = config::endpoint_info_b64(device_name);

    let addrs: Vec<IpAddr> = if_addrs::get_if_addrs()?
        .into_iter()
        .filter(|i| !i.is_loopback())
        .map(|i| i.ip())
        .filter(|ip| ip.is_ipv4())
        .collect();

    let info = ServiceInfo::new(
        &service_type,
        &instance,
        &format!("{}.local.", instance),
        &addrs[..],
        port,
        &[("n", endpoint_info_b64.as_str())][..],
    )?;

    let fullname = info.get_fullname().to_string();

    let daemon = ServiceDaemon::new()?;
    daemon.register(info)?;

    info!(
        "mDNS yayında: type={} instance={} name=\"{}\" endpoint_id={}",
        service_type,
        instance,
        device_name,
        String::from_utf8_lossy(&endpoint_id)
    );

    Ok(MdnsHandle { daemon, fullname })
}
