//! Platform clipboard facade.
//!
//! macOS uses its native pasteboard; Linux uses the Wayland data-control
//! protocol, so no X11/XWayland helper process is involved. Only the small set
//! of types the phone protocol understands is supported.
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "linux")]
mod wayland;

#[cfg(target_os = "macos")]
pub use macos::Reader;
#[cfg(target_os = "linux")]
pub use wayland::Reader;

pub enum Content {
    Text(String),
    Files(Vec<std::path::PathBuf>),
    Image(Image),
    Unsupported,
}
pub const MAX_IMAGE_BYTES: usize = 32 * 1024 * 1024;
pub struct Image {
    pub name: &'static str,
    pub bytes: Vec<u8>,
}

/// Writes text so that any application can paste it, without an owner process
/// staying alive on macOS.
pub fn write_text(text: &str) -> anyhow::Result<()> {
    #[cfg(target_os = "macos")]
    {
        macos::write_text(text).map(|_| ())
    }
    #[cfg(target_os = "linux")]
    {
        wayland::copy_text(text)
    }
}

/// One-shot diagnostic read. This is not a persistent paste helper: on Linux
/// the selection is owned by this process only while it runs.
pub fn read_text() -> anyhow::Result<Option<String>> {
    #[cfg(target_os = "macos")]
    {
        Ok(macos::read_text())
    }
    #[cfg(target_os = "linux")]
    {
        wayland::read_text()
    }
}
