//! Device discovery facade.
//!
//! macOS uses the system DNS-SD API; Linux uses a pure Rust mDNS client. Both
//! parse the same `_lyra-mdns._udp.local.` advertisement and never log device
//! identifiers. The implementation lives in a platform module.
use serde::Serialize;
use std::net::SocketAddr;
use std::time::Duration;

#[cfg(target_os = "linux")]
#[path = "discovery/linux.rs"]
mod linux;
#[cfg(target_os = "macos")]
#[path = "discovery/macos.rs"]
mod macos;

#[derive(Serialize)]
pub struct Endpoint {
    pub host: String,
    /// macOS reports the interface index; Linux aggregates every interface.
    pub interface: u32,
    pub kcp_port: u16,
    pub device_type: u8,
    pub model: Option<String>,
    /// Cached addresses; never serialized so saved listings stay unchanged.
    #[serde(skip)]
    pub resolved: Vec<SocketAddr>,
}

impl Endpoint {
    pub fn socket_addresses(&self) -> &[SocketAddr] {
        &self.resolved
    }
}

/// Scans the local network for phones advertising this protocol.
pub fn discover(timeout: Duration) -> anyhow::Result<Vec<Endpoint>> {
    anyhow::ensure!(
        timeout <= Duration::from_secs(30),
        "Discovery timeout exceeds limit"
    );
    #[cfg(target_os = "macos")]
    {
        macos::discover(timeout)
    }
    #[cfg(target_os = "linux")]
    {
        linux::discover(timeout)
    }
}
