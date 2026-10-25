//! Private handoff from the sandboxed macOS Share extension. Each request owns
//! its staged files until Android confirms completion or the request fails.
use std::{
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

pub(crate) struct Request {
    directory: PathBuf,
    pub offer: std::sync::Arc<crate::clipboard_files::Offer>,
    finished: bool,
    last_progress: std::time::Instant,
}
impl Request {
    pub fn next(root: &Path) -> anyhow::Result<Option<Self>> {
        let entries = match std::fs::read_dir(root) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
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
            let names: Vec<String> = serde_json::from_slice(&bytes)?;
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
                offer: std::sync::Arc::new(offer),
                finished: false,
                last_progress: std::time::Instant::now(),
            };
            request.status("connecting", 0)?;
            return Ok(Some(request));
        }
        Ok(None)
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
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let temp = self.directory.join(format!(
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
            file.write_all(&serde_json::to_vec(
                &serde_json::json!({"state": state, "sent": sent}),
            )?)?;
            std::fs::rename(&temp, self.directory.join("status.json"))?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(temp);
        }
        result?;
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

pub(crate) fn root() -> Option<PathBuf> {
    Some(PathBuf::from(std::env::var_os("HOME")?).join(
        "Library/Containers/com.cyeam.miclip.share/Data/Library/Application Support/MiClip/Outbox",
    ))
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
        std::fs::write(dir.join("request.json"), br#"["test.txt"]"#).unwrap();
        let request = Request::next(&root).unwrap().unwrap();
        assert!(Request::next(&root).unwrap().is_none());
        assert_eq!(request.offer.read(0, 0).unwrap(), b"synthetic");
        drop(request);
        let status: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.join("status.json")).unwrap()).unwrap();
        assert_eq!(status["state"], "failed");
        std::fs::remove_file(dir.join("status.json")).unwrap();
        std::fs::write(dir.join("request.json"), br#"["../private.txt"]"#).unwrap();
        assert!(Request::next(&root).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
