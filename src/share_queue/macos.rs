//! Private handoff from the sandboxed macOS Share extension.
//!
//! Each request owns its staged files until the phone confirms completion or the
//! request fails. The directory is created and removed by the extension.
use super::{ShareDevice, validate_selected};
use std::{
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

pub(crate) struct Request {
    directory: PathBuf,
    pub target: std::net::SocketAddr,
    pub offer: std::sync::Arc<crate::clipboard_files::Offer>,
    finished: bool,
    failure: Option<String>,
    last_progress: std::time::Instant,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Description {
    files: Vec<String>,
    target: std::net::SocketAddr,
}

struct Candidate {
    directory: PathBuf,
    description: Description,
}

/// Ready, unclaimed requests, newest first, restricted to `target` when given.
fn candidates(root: &Path, target: Option<std::net::SocketAddr>) -> anyhow::Result<Vec<Candidate>> {
    let entries = match std::fs::read_dir(root) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    let mut found = Vec::new();
    for entry in entries {
        let entry = entry?;
        let directory = entry.path();
        if !entry.file_type()?.is_dir() || directory.extension().is_none_or(|s| s != "ready") {
            continue;
        }
        let metadata = std::fs::symlink_metadata(&directory)?;
        anyhow::ensure!(
            metadata.uid() == unsafe { getuid() } && metadata.mode() & 0o077 == 0,
            "Insecure share request directory"
        );
        let age = metadata.modified()?.elapsed().unwrap_or_default();
        // Never silently replay a share after the UI timed out or after restart.
        if age.as_secs() > 120 || directory.join("status.json").exists() {
            continue;
        }
        let bytes = std::fs::read(directory.join("request.json"))?;
        anyhow::ensure!(bytes.len() <= 65536, "Oversized share request");
        let description: Description = match serde_json::from_slice(&bytes) {
            Ok(description) => description,
            Err(_) => {
                // Old extensions did not carry a selected target. Never
                // guess one, or let a stale request block newer selections.
                let _ = write_status(
                    &directory,
                    "failed",
                    0,
                    Some("Select a device in the updated Clip sharing window"),
                );
                continue;
            }
        };
        validate_selected(description.target)?;
        if target.is_some_and(|target| target != description.target) {
            continue;
        }
        found.push(Candidate {
            directory,
            description,
        });
    }
    Ok(found)
}

impl Request {
    #[cfg(test)]
    pub fn next(root: &Path) -> anyhow::Result<Option<Self>> {
        Self::next_for(root, None)
    }
    pub fn next_for(
        root: &Path,
        target: Option<std::net::SocketAddr>,
    ) -> anyhow::Result<Option<Self>> {
        let Some(Candidate {
            directory,
            description,
        }) = candidates(root, target)?.into_iter().next()
        else {
            return Ok(None);
        };
        let names = description.files;
        anyhow::ensure!((1..=128).contains(&names.len()), "Invalid share file count");
        let paths = names
            .iter()
            .map(|name| {
                anyhow::ensure!(crate::file_store::valid_name(name), "Unsafe share filename");
                Ok(directory.join("files").join(name))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let offer = crate::clipboard_files::Offer::open(paths, 0)?;
        let mut request = Self {
            directory,
            target: description.target,
            offer: std::sync::Arc::new(offer),
            finished: false,
            failure: None,
            last_progress: std::time::Instant::now(),
        };
        request.status("connecting", 0)?;
        Ok(Some(request))
    }
    pub fn exists(&self) -> bool {
        self.directory.is_dir()
    }
    pub fn status(&mut self, state: &str, sent: u64) -> anyhow::Result<()> {
        if state == "sending"
            && self.last_progress.elapsed() < std::time::Duration::from_millis(250)
        {
            return Ok(());
        }
        self.last_progress = std::time::Instant::now();
        write_status(&self.directory, state, sent, self.failure.as_deref())
    }
    pub fn fail(&mut self, message: &str) -> anyhow::Result<()> {
        self.failure = Some(message.to_owned());
        self.status("failed", 0)?;
        self.finished = true;
        Ok(())
    }
    pub fn complete(&mut self) -> anyhow::Result<()> {
        self.status("completed", self.offer.files.iter().map(|f| f.size).sum())?;
        self.finished = true;
        Ok(())
    }
}
impl Drop for Request {
    fn drop(&mut self) {
        if !self.finished && self.exists() {
            let _ = self.status("failed", 0);
        }
    }
}
unsafe extern "C" {
    fn getuid() -> u32;
}

/// Writes a status file atomically inside the request directory.
fn write_status(
    directory: &Path,
    state: &str,
    sent: u64,
    message: Option<&str>,
) -> anyhow::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let temp = directory.join(format!(
        "status-{:016x}.tmp",
        u64::from_ne_bytes(crate::private::random()?)
    ));
    // Do not recreate a directory removed by the extension's Cancel action.
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)?;
    let result = (|| -> anyhow::Result<()> {
        file.write_all(&serde_json::to_vec(&serde_json::json!({
            "state": state,
            "sent": sent,
            "message": message,
        }))?)?;
        std::fs::rename(&temp, directory.join("status.json"))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temp);
    }
    result?;
    Ok(())
}

pub(crate) fn root() -> Option<PathBuf> {
    Some(PathBuf::from(std::env::var_os("HOME")?).join(
        "Library/Containers/com.cyeam.miclip.share/Data/Library/Application Support/MiClip/Outbox",
    ))
}

/// Inspect only ready, unclaimed requests. Opening the share sheet or loading
/// files does not create one: the user must first click a device to send.
pub fn pending_target() -> Option<std::net::SocketAddr> {
    let root = root()?;
    candidates(&root, None)
        .ok()?
        .into_iter()
        .next()
        .map(|candidate| candidate.description.target)
}

/// Claims the pending request for `target`, at most once per ready directory.
pub(super) fn take_for(target: std::net::SocketAddr) -> anyhow::Result<Option<Request>> {
    let Some(root) = root() else {
        return Ok(None);
    };
    Request::next_for(&root, Some(target))
}

/// Identity of the outstanding request, captured before a session attempt.
pub struct FailureScope {
    directory: Option<PathBuf>,
}

pub(super) fn failure_scope() -> Option<FailureScope> {
    let directory = root()
        .and_then(|root| candidates(&root, None).ok())
        .and_then(|found| found.into_iter().next())
        .map(|candidate| candidate.directory);
    Some(FailureScope { directory })
}

impl FailureScope {
    /// Settles only the request this scope was captured for; a newer request is
    /// never failed by a late error from an older session.
    pub fn fail_if_pending(&self, message: &str) {
        let Some(directory) = &self.directory else {
            return;
        };
        if directory.join("status.json").exists() {
            return;
        }
        let _ = write_status(directory, "failed", 0, Some(message));
    }
}

pub(super) fn take_device_refresh() -> bool {
    root()
        .and_then(|p| p.parent().map(|p| p.join("refresh-devices")))
        .is_some_and(|p| std::fs::remove_file(p).is_ok())
}

static DISCOVERED: std::sync::Mutex<Vec<ShareDevice>> = std::sync::Mutex::new(Vec::new());
static CONNECTED: std::sync::Mutex<Option<std::net::SocketAddr>> = std::sync::Mutex::new(None);
pub(super) fn set_connected(target: Option<std::net::SocketAddr>) {
    *CONNECTED.lock().unwrap() = target;
    let devices = DISCOVERED.lock().unwrap().clone();
    let _ = write_devices(devices);
}
pub(super) fn devices() -> Vec<ShareDevice> {
    let mut devices = DISCOVERED.lock().unwrap().clone();
    if let Some(endpoint) = *CONNECTED.lock().unwrap()
        && !devices.iter().any(|d| d.endpoint == endpoint)
    {
        devices.push(ShareDevice {
            name: "已连接的手机".into(),
            device_type: 1,
            endpoint,
        });
    }
    devices
}
/// Short-lived, private device catalogue for the sandboxed picker. No account
/// information, certificates, clipboard data, or file contents enter this file.
pub(super) fn publish_devices(devices: Vec<ShareDevice>) -> anyhow::Result<()> {
    *DISCOVERED.lock().unwrap() = devices.clone();
    write_devices(devices)
}
fn write_devices(devices: Vec<ShareDevice>) -> anyhow::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    let Some(root) = root().and_then(|p| p.parent().map(Path::to_path_buf)) else {
        return Ok(());
    };
    // Wait for macOS/the extension to create its own sandbox container.
    // Creating another app's container from outside can prevent sandbox launch.
    if !root.parent().is_some_and(Path::exists) {
        return Ok(());
    }
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&root)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    crate::private::save(
        &root.join("devices.json"),
        &serde_json::to_vec(&serde_json::json!({"updated": now, "devices": devices}))?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn share_is_claimed_once_and_failure_is_published_on_disconnect() {
        let root = std::env::temp_dir().join(format!(
            "clip-queue-{:016x}",
            u64::from_ne_bytes(crate::private::random().unwrap())
        ));
        let dir = root.join("request.ready");
        std::fs::create_dir_all(dir.join("files")).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(dir.join("files/test.txt"), b"synthetic").unwrap();
        std::fs::write(
            dir.join("request.json"),
            br#"{"files":["test.txt"],"target":"127.0.0.1:1"}"#,
        )
        .unwrap();
        let request = Request::next(&root).unwrap().unwrap();
        assert!(Request::next(&root).unwrap().is_none());
        assert_eq!(request.offer.read(0, 0).unwrap(), b"synthetic");
        drop(request);
        let status: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.join("status.json")).unwrap()).unwrap();
        assert_eq!(status["state"], "failed");
        std::fs::remove_file(dir.join("status.json")).unwrap();
        std::fs::write(
            dir.join("request.json"),
            br#"{"files":["../private.txt"],"target":"127.0.0.1:1"}"#,
        )
        .unwrap();
        assert!(Request::next(&root).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(test)]
mod selection_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn queued_selection_never_falls_back_to_another_connected_phone() {
        let root = std::env::temp_dir().join(format!(
            "clip-selection-{:016x}",
            u64::from_ne_bytes(crate::private::random().unwrap())
        ));
        let dir = root.join("request.ready");
        std::fs::create_dir_all(dir.join("files")).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(dir.join("files/test.txt"), b"synthetic").unwrap();
        // A pre-selection request is invalid; it must not auto-pick a phone.
        std::fs::write(dir.join("request.json"), br#"{"files":["test.txt"]}"#).unwrap();
        assert!(
            Request::next_for(&root, Some("127.0.0.1:2".parse().unwrap()))
                .unwrap()
                .is_none()
        );
        assert!(dir.join("status.json").exists());
        std::fs::remove_file(dir.join("status.json")).unwrap();
        std::fs::write(
            dir.join("request.json"),
            br#"{"files":["test.txt"],"target":"127.0.0.1:1"}"#,
        )
        .unwrap();
        assert!(
            Request::next_for(&root, Some("127.0.0.1:2".parse().unwrap()))
                .unwrap()
                .is_none()
        );
        assert!(!dir.join("status.json").exists());
        let mut request = Request::next_for(&root, Some("127.0.0.1:1".parse().unwrap()))
            .unwrap()
            .unwrap();
        request.fail("Phone did not accept the request").unwrap();
        let status: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.join("status.json")).unwrap()).unwrap();
        assert_eq!(status["state"], "failed");
        assert_eq!(status["message"], "Phone did not accept the request");
        assert_eq!(status["sent"], 0);
        drop(request);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn late_failure_touches_only_the_captured_request() {
        let root = std::env::temp_dir().join(format!(
            "clip-scope-{:016x}",
            u64::from_ne_bytes(crate::private::random().unwrap())
        ));
        let directory = root.join("request.ready");
        std::fs::create_dir_all(directory.join("files")).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(directory.join("files/test.txt"), b"synthetic").unwrap();
        std::fs::write(
            directory.join("request.json"),
            br#"{"files":["test.txt"],"target":"127.0.0.1:1"}"#,
        )
        .unwrap();
        let scope = FailureScope {
            directory: Some(directory.clone()),
        };
        // A request that already settled is never overwritten by a late error.
        write_status(&directory, "completed", 3, None).unwrap();
        scope.fail_if_pending("late failure");
        let status: serde_json::Value =
            serde_json::from_slice(&std::fs::read(directory.join("status.json")).unwrap()).unwrap();
        assert_eq!(status["state"], "completed");
        std::fs::remove_dir_all(root).unwrap();
    }
}
