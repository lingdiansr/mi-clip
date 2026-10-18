//! Bounded streaming storage. Publication happens only after size/hash checks.
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

pub(crate) const MAX_FILE_SIZE: u64 = 8 * 1024 * 1024 * 1024;

pub(crate) struct IncomingFile {
    directory: PathBuf,
    name: String,
    temporary: PathBuf,
    file: File,
    expected: u64,
    received: u64,
    hash: Sha256,
}

pub(crate) fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 240
        && !matches!(name, "." | "..")
        && !name
            .chars()
            .any(|c| c.is_control() || matches!(c, '/' | '\\' | ':'))
}

impl IncomingFile {
    pub fn create(directory: &Path, name: &str, expected: u64) -> anyhow::Result<Self> {
        anyhow::ensure!(valid_name(name), "Unsafe incoming filename");
        anyhow::ensure!(
            expected <= MAX_FILE_SIZE,
            "Incoming file exceeds size limit"
        );
        if !directory.exists() {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(directory)?;
        }
        anyhow::ensure!(
            fs::symlink_metadata(directory)?.file_type().is_dir(),
            "Receive location must be a real directory"
        );
        let temporary = directory.join(format!(
            ".clip-incoming-{:016x}",
            u64::from_ne_bytes(crate::private::random()?)
        ));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        Ok(Self {
            directory: directory.to_owned(),
            name: name.into(),
            temporary,
            file,
            expected,
            received: 0,
            hash: Sha256::new(),
        })
    }
    pub fn write(&mut self, bytes: &[u8]) -> anyhow::Result<()> {
        let received = self
            .received
            .checked_add(u64::try_from(bytes.len())?)
            .ok_or_else(|| anyhow::anyhow!("Incoming file length overflow"))?;
        anyhow::ensure!(
            received <= self.expected,
            "Incoming file exceeds advertised length"
        );
        self.file.write_all(bytes)?;
        self.hash.update(bytes);
        self.received = received;
        Ok(())
    }
    pub fn received(&self) -> u64 {
        self.received
    }

    /// Call only after an authenticated transfer-complete message. If the wire
    /// protocol provides a checksum, pass it here before acknowledging success.
    pub fn commit(self, expected_sha256: Option<[u8; 32]>) -> anyhow::Result<PathBuf> {
        anyhow::ensure!(
            self.received == self.expected,
            "Incoming file is incomplete"
        );
        let digest: [u8; 32] = self.hash.clone().finalize().into();
        if let Some(expected) = expected_sha256 {
            anyhow::ensure!(digest == expected, "Incoming file checksum mismatch");
        }
        self.file.sync_all()?;
        let original = Path::new(&self.name);
        let stem = original
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or(&self.name);
        let extension = original.extension().and_then(|s| s.to_str());
        for collision in 0..1000 {
            let name = if collision == 0 {
                self.name.clone()
            } else {
                format!(
                    "{stem} ({collision}){}",
                    extension.map(|ext| format!(".{ext}")).unwrap_or_default()
                )
            };
            let destination = self.directory.join(name);
            // An atomic hard link on the same filesystem publishes the complete
            // file, and refuses existing files, directories and symlinks alike.
            match fs::hard_link(&self.temporary, &destination) {
                Ok(()) => {
                    let _ = fs::remove_file(&self.temporary);
                    let _ = File::open(&self.directory).and_then(|dir| dir.sync_all());
                    return Ok(destination);
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        }
        anyhow::bail!("Too many incoming filename collisions")
    }
}
impl Drop for IncomingFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.temporary);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn interrupted_or_corrupt_files_stay_unpublished_and_existing_files_survive() {
        let root = std::env::temp_dir().join(format!(
            "clip-store-test-{:016x}",
            u64::from_ne_bytes(crate::private::random().unwrap())
        ));
        fs::create_dir(&root).unwrap();
        for name in [
            "../escape",
            "..",
            "/absolute",
            "a/b",
            "a\\b",
            "C:drive",
            "nul\0name",
        ] {
            assert!(IncomingFile::create(&root, name, 3).is_err());
        }
        {
            let mut file = IncomingFile::create(&root, "sample.txt", 6).unwrap();
            file.write(b"abc").unwrap();
            assert_eq!(file.received(), 3);
            assert!(file.commit(None).is_err());
        }
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        {
            let mut file = IncomingFile::create(&root, "sample.txt", 3).unwrap();
            assert!(file.write(b"abcd").is_err());
            file.write(b"abc").unwrap();
            assert!(file.commit(Some([0; 32])).is_err());
        }
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        fs::write(root.join("sample.txt"), b"existing").unwrap();
        let mut file = IncomingFile::create(&root, "sample.txt", 3).unwrap();
        file.write(b"a").unwrap();
        file.write(b"bc").unwrap();
        let saved = file.commit(Some(Sha256::digest(b"abc").into())).unwrap();
        assert_eq!(saved.file_name().unwrap(), "sample (1).txt");
        assert_eq!(fs::read(saved).unwrap(), b"abc");
        assert_eq!(fs::read(root.join("sample.txt")).unwrap(), b"existing");
        assert_eq!(fs::read_dir(&root).unwrap().count(), 2);
        fs::remove_dir_all(root).unwrap();
    }
}
