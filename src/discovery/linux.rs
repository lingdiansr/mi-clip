//! Linux mDNS discovery over the pure Rust `mdns-sd` client; no avahi daemon,
//! no subprocess, and no X11/XWayland dependency.
use super::Endpoint;
use crate::advertisement::Advertisement;
use base64::{Engine, engine::general_purpose::STANDARD};
use mdns_sd::{DaemonEvent, RecvTimeoutError, ServiceDaemon, ServiceEvent};
use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};

const SERVICE: &str = "_lyra-mdns._udp.local.";
const MAX_ENDPOINTS: usize = 64;
/// Longest a shutdown receipt may take before the daemon is abandoned.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);

/// Stops browsing and waits for the daemon thread on every exit path.
struct Daemon(Option<ServiceDaemon>);
impl Drop for Daemon {
    fn drop(&mut self) {
        if let Some(daemon) = self.0.take() {
            let _ = daemon.stop_browse(SERVICE);
            if let Ok(receipt) = daemon.shutdown() {
                let _ = receipt.recv_timeout(SHUTDOWN_TIMEOUT);
            }
        }
    }
}

pub(super) fn discover(timeout: Duration) -> anyhow::Result<Vec<Endpoint>> {
    let daemon =
        ServiceDaemon::new().map_err(|error| anyhow::anyhow!("mDNS 守护线程启动失败：{error}"))?;
    let mut guard = Daemon(Some(daemon));
    let daemon = guard.0.as_ref().unwrap();
    let events = daemon
        .browse(SERVICE)
        .map_err(|error| anyhow::anyhow!("mDNS 浏览失败：{error}"))?;
    let monitor = daemon
        .monitor()
        .map_err(|error| anyhow::anyhow!("mDNS 事件通道失败：{error}"))?;
    let deadline = Instant::now() + timeout;
    let mut found: Vec<(String, Endpoint)> = Vec::new();
    while Instant::now() < deadline {
        // Daemon errors are visible failures, never an empty device list.
        while let Ok(event) = monitor.try_recv() {
            if let DaemonEvent::Error(error) = event {
                anyhow::bail!("mDNS 发现失败：{error}");
            }
        }
        let wait = deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(200));
        match events.recv_timeout(wait) {
            Ok(ServiceEvent::ServiceResolved(service)) => {
                let Some(value) = service.get_property_val_str("AppData") else {
                    continue;
                };
                let Ok(bytes) = STANDARD.decode(value) else {
                    continue;
                };
                let Ok(ad) = Advertisement::parse(&bytes) else {
                    continue;
                };
                let Some(port) = ad.kcp_port.filter(|port| *port != 0) else {
                    continue;
                };
                // The SRV record's port is the advertisement service port, never
                // the phone's KCP port, which only AppData carries.
                let host = service.get_hostname();
                if host.is_empty() || host.len() > 255 || found.len() >= MAX_ENDPOINTS {
                    continue;
                }
                let mut resolved: Vec<SocketAddr> = service
                    .get_addresses_v4()
                    .into_iter()
                    .map(|address| SocketAddr::from((address, port)))
                    .collect();
                resolved.sort();
                resolved.dedup();
                // A record without any IPv4 address cannot be connected to.
                if resolved.is_empty() {
                    continue;
                }
                let endpoint = Endpoint {
                    host: host.to_owned(),
                    // Aggregated across interfaces, so no single index applies.
                    interface: 0,
                    kcp_port: port,
                    device_type: ad.device_type,
                    model: ad
                        .model
                        .filter(|model| !model.chars().any(char::is_control))
                        .map(str::to_owned),
                    resolved,
                };
                match found
                    .iter_mut()
                    .find(|(name, _)| name == service.fullname.as_str())
                {
                    Some((_, existing)) => *existing = endpoint,
                    None => found.push((service.fullname.clone(), endpoint)),
                }
            }
            Ok(ServiceEvent::ServiceRemoved(_, fullname)) => {
                found.retain(|(name, _)| name != &fullname);
            }
            Ok(_) => (),
            Err(RecvTimeoutError::Timeout) => (),
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    // One phone may answer through several interfaces; merge identical records.
    let mut merged: Vec<Endpoint> = Vec::new();
    for (_, endpoint) in found {
        match merged
            .iter_mut()
            .find(|known| known.host == endpoint.host && known.kcp_port == endpoint.kcp_port)
        {
            Some(known) => {
                known.resolved.extend(endpoint.resolved);
                known.resolved.sort();
                known.resolved.dedup();
            }
            None => merged.push(endpoint),
        }
    }
    merged.sort_by(|a, b| a.host.cmp(&b.host).then(a.kcp_port.cmp(&b.kcp_port)));
    merged.truncate(MAX_ENDPOINTS);
    Ok(merged)
}
