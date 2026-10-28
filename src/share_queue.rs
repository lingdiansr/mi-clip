//! Platform facade for outgoing file shares.
//!
//! macOS accepts requests from its sandboxed Share extension through a private
//! Outbox directory. Linux keeps a single in-memory task because a native
//! window chooses the target. Both expose the same worker-facing surface.
use std::net::SocketAddr;

#[cfg(target_os = "linux")]
#[path = "share_queue/linux.rs"]
mod linux;
#[cfg(target_os = "macos")]
#[path = "share_queue/macos.rs"]
mod macos;

#[cfg(target_os = "linux")]
pub use linux::FailureScope;
#[cfg(target_os = "linux")]
pub(crate) use linux::Request;
#[cfg(all(target_os = "linux", test))]
pub(crate) use linux::Queue;
#[cfg(target_os = "linux")]
pub use linux::{LocalShare, ShareProgress, ShareState};
#[cfg(target_os = "macos")]
pub use macos::FailureScope;
#[cfg(target_os = "macos")]
pub(crate) use macos::Request;

/// A phone row offered to the share picker. No account data.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct ShareDevice {
    pub name: String,
    pub device_type: u8,
    pub endpoint: SocketAddr,
}

pub fn validate_selected(target: SocketAddr) -> anyhow::Result<()> {
    anyhow::ensure!(
        target.port() != 0 && !target.ip().is_unspecified() && !target.ip().is_multicast(),
        "Invalid selected device"
    );
    Ok(())
}

/// Target of a share task that is still waiting to be picked up.
pub fn pending_target() -> Option<SocketAddr> {
    #[cfg(target_os = "macos")]
    {
        macos::pending_target()
    }
    #[cfg(target_os = "linux")]
    {
        linux::queue().pending_target()
    }
}

/// Claims the pending request for `target`, at most once.
pub(crate) fn take_for(target: SocketAddr) -> anyhow::Result<Option<Request>> {
    #[cfg(target_os = "macos")]
    {
        macos::take_for(target)
    }
    #[cfg(target_os = "linux")]
    {
        Ok(linux::queue().take_for(target))
    }
}

/// Captures the identity of the outstanding task before a session attempt so a
/// late failure cannot settle a newer request.
pub fn failure_scope() -> Option<FailureScope> {
    #[cfg(target_os = "macos")]
    {
        macos::failure_scope()
    }
    #[cfg(target_os = "linux")]
    {
        linux::queue().failure_scope()
    }
}

/// Queues one share task for the native picker (Linux only).
#[cfg(target_os = "linux")]
pub fn enqueue(paths: Vec<std::path::PathBuf>, target: SocketAddr) -> anyhow::Result<LocalShare> {
    linux::queue().enqueue(paths, target)
}

/// Publishes the discovery catalogue for the picker.
pub fn publish_devices(devices: Vec<ShareDevice>) -> anyhow::Result<()> {
    #[cfg(target_os = "macos")]
    {
        macos::publish_devices(devices)
    }
    #[cfg(target_os = "linux")]
    {
        linux::publish_devices(devices)
    }
}

/// Records the phone the session is authenticated with.
pub fn set_connected(target: Option<SocketAddr>) {
    #[cfg(target_os = "macos")]
    {
        macos::set_connected(target)
    }
    #[cfg(target_os = "linux")]
    {
        linux::set_connected(target)
    }
}

/// Consumes a pending catalogue refresh from the platform picker.
pub fn take_device_refresh() -> bool {
    #[cfg(target_os = "macos")]
    {
        macos::take_device_refresh()
    }
    #[cfg(target_os = "linux")]
    {
        linux::take_device_refresh()
    }
}

/// The current discovery catalogue, including the connected phone.
pub fn devices() -> Vec<ShareDevice> {
    #[cfg(target_os = "macos")]
    {
        macos::devices()
    }
    #[cfg(target_os = "linux")]
    {
        linux::devices()
    }
}
