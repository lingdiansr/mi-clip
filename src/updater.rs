//! Signed, bounded single-binary updates. No updater framework or unsigned fallback.
use crate::{http, private, update_key};
use base64::{Engine, engine::general_purpose::STANDARD};
use p256::ecdsa::{
    Signature, SigningKey, VerifyingKey,
    signature::{Signer, Verifier},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

pub const REPOSITORY: &str = match option_env!("MI_CLIP_UPDATE_REPOSITORY") {
    Some(v) => v,
    None => "",
};
const MAX_BINARY: usize = 64 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    payload: String,
    signature: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Release {
    version: String,
    arch: String,
    size: usize,
    sha256: String,
    url: String,
}

fn version(value: &str) -> anyhow::Result<[u64; 3]> {
    let pieces: Vec<_> = value.split('.').collect();
    anyhow::ensure!(pieces.len() == 3, "Expected a stable semantic version");
    let mut numbers = [0; 3];
    for (index, piece) in pieces.into_iter().enumerate() {
        anyhow::ensure!(
            !piece.is_empty()
                && (piece.len() == 1 || !piece.starts_with('0'))
                && piece.bytes().all(|b| b.is_ascii_digit()),
            "Invalid release version"
        );
        numbers[index] = piece.parse()?;
    }
    Ok(numbers)
}
fn repository(value: &str) -> bool {
    let pieces: Vec<_> = value.split('/').collect();
    pieces.len() == 2
        && pieces.iter().all(|p| {
            !p.is_empty()
                && *p != "."
                && *p != ".."
                && p.len() <= 100
                && p.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
        })
}
fn asset(arch: &str) -> String {
    format!("mi-clip-macos-{arch}")
}
fn release_url(repo: &str, release: &Release) -> String {
    format!(
        "https://github.com/{repo}/releases/download/v{}/{}",
        release.version,
        asset(&release.arch)
    )
}
fn verify_feed(
    bytes: &[u8],
    key: &VerifyingKey,
    repo: &str,
    arch: &str,
) -> anyhow::Result<Release> {
    anyhow::ensure!(
        bytes.len() <= 65536 && repository(repo),
        "Invalid update metadata"
    );
    let envelope: Envelope = serde_json::from_slice(bytes)?;
    let payload = STANDARD.decode(envelope.payload)?;
    let signature = Signature::from_der(&STANDARD.decode(envelope.signature)?)?;
    key.verify(&payload, &signature)
        .map_err(|_| anyhow::anyhow!("Update signature rejected"))?;
    let release: Release = serde_json::from_slice(&payload)?;
    version(&release.version)?;
    anyhow::ensure!(
        release.arch == arch && matches!(arch, "x86_64" | "aarch64"),
        "Update architecture mismatch"
    );
    anyhow::ensure!(
        (32..=MAX_BINARY).contains(&release.size)
            && release.sha256.len() == 64
            && release.sha256.bytes().all(|b| b.is_ascii_hexdigit()),
        "Invalid update size or digest"
    );
    anyhow::ensure!(
        release.url == release_url(repo, &release),
        "Update URL outside release repository"
    );
    Ok(release)
}
fn verify_binary(bytes: &[u8], release: &Release) -> anyhow::Result<()> {
    anyhow::ensure!(
        bytes.len() == release.size && bytes.len() <= MAX_BINARY,
        "Update length mismatch"
    );
    let digest: String = Sha256::digest(bytes)
        .iter()
        .map(|v| format!("{v:02x}"))
        .collect();
    anyhow::ensure!(digest == release.sha256, "Update digest mismatch");
    let cpu = match release.arch.as_str() {
        "x86_64" => 0x01000007u32,
        "aarch64" => 0x0100000c,
        _ => anyhow::bail!("Unsupported update architecture"),
    };
    anyhow::ensure!(
        bytes.get(..4) == Some(&[0xcf, 0xfa, 0xed, 0xfe])
            && bytes.get(4..8) == Some(cpu.to_le_bytes().as_slice())
            && bytes.get(12..16) == Some(2u32.to_le_bytes().as_slice()),
        "Update is not a matching Mach-O executable"
    );
    Ok(())
}

pub struct PendingUpdate {
    release: Release,
    staged: PathBuf,
    executable: PathBuf,
}
impl PendingUpdate {
    pub fn version(&self) -> &str {
        &self.release.version
    }
    pub fn validate(&self) -> anyhow::Result<()> {
        verify_binary(&fs::read(&self.staged)?, &self.release)
    }
}
impl Drop for PendingUpdate {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.staged);
    }
}
pub enum Check {
    Current,
    Unpublished,
    Ready(PendingUpdate),
}

pub fn check() -> anyhow::Result<Check> {
    anyhow::ensure!(repository(REPOSITORY), "Update repository not configured");
    let arch = std::env::consts::ARCH;
    let url = format!(
        "https://github.com/{REPOSITORY}/releases/latest/download/manifest-macos-{arch}.json"
    );
    let response = http::download(&url, 65536)?;
    if response.status == 404 {
        return Ok(Check::Unpublished);
    }
    anyhow::ensure!(response.status == 200, "Update feed request failed");
    let key = VerifyingKey::from_sec1_bytes(&STANDARD.decode(update_key::PUBLIC_KEY)?)?;
    let release = verify_feed(&response.body, &key, REPOSITORY, arch)?;
    if version(&release.version)? <= version(env!("CARGO_PKG_VERSION"))? {
        return Ok(Check::Current);
    }
    let response = http::download(&release.url, release.size)?;
    anyhow::ensure!(response.status == 200, "Update download failed");
    verify_binary(&response.body, &release)?;
    let executable = std::env::current_exe()?.canonicalize()?;
    let parent = executable
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Executable directory unavailable"))?;
    let nonce: String = private::random::<16>()?
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let staged = parent.join(format!(".mi-clip-update-{nonce}"));
    private::save(&staged, &response.body)?;
    Ok(Check::Ready(PendingUpdate {
        release,
        staged,
        executable,
    }))
}

fn health_file(executable: &Path) -> anyhow::Result<PathBuf> {
    let nonce: String = private::random::<16>()?
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    Ok(executable
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Missing executable directory"))?
        .join(format!(".mi-clip-health-{nonce}")))
}
pub fn mark_ready() -> anyhow::Result<()> {
    let Some(value) = std::env::var_os("MICLIP_UPDATE_READY") else {
        return Ok(());
    };
    let path = PathBuf::from(value);
    let executable = std::env::current_exe()?.canonicalize()?;
    let name = path.file_name().and_then(|v| v.to_str()).unwrap_or("");
    anyhow::ensure!(
        path.parent() == executable.parent()
            && name.starts_with(".mi-clip-health-")
            && name.len() == ".mi-clip-health-".len() + 32
            && name[".mi-clip-health-".len()..]
                .bytes()
                .all(|b| b.is_ascii_hexdigit()),
        "Invalid update readiness path"
    );
    private::save(&path, env!("CARGO_PKG_VERSION").as_bytes())
}

/// Called during application shutdown after the instance lock is released.
/// Preserve the old inode until the replacement reports a functioning status bar.
pub fn install(pending: PendingUpdate, arguments: &[String]) -> anyhow::Result<()> {
    use std::process::{Command, Stdio};
    let backup = health_file(&pending.executable)?.with_extension("previous");
    let ready = health_file(&pending.executable)?;
    let result = (|| -> anyhow::Result<()> {
        pending.validate()?;
        fs::hard_link(&pending.executable, &backup)?;
        fs::set_permissions(&pending.staged, fs::Permissions::from_mode(0o755))?;
        fs::File::open(&pending.staged)?.sync_all()?;
        fs::rename(&pending.staged, &pending.executable)?;
        let mut child = Command::new(&pending.executable)
            .args(arguments)
            .env("MICLIP_UPDATE_READY", &ready)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        while std::time::Instant::now() < deadline {
            if fs::read(&ready).ok().as_deref() == Some(pending.version().as_bytes()) {
                let _ = fs::remove_file(&ready);
                return Ok(());
            }
            if child.try_wait()?.is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        let _ = child.kill();
        let _ = child.wait();
        anyhow::bail!("Updated process failed its startup health check")
    })();
    let _ = fs::remove_file(&ready);
    if result.is_ok() {
        let _ = fs::remove_file(backup);
    } else {
        if backup.exists() {
            fs::rename(&backup, &pending.executable)?;
        }
        let _ = Command::new(&pending.executable)
            .args(arguments)
            .env_remove("MICLIP_UPDATE_READY")
            .env("MICLIP_UPDATE_ROLLBACK", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
    }
    result
}

/// Local release tooling. Config and private signing key must remain outside the repository.
pub fn sign_release(config: &Path, output: &Path) -> anyhow::Result<()> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Config {
        version: String,
        arch: String,
        repository: String,
        binary: PathBuf,
        private_key: PathBuf,
    }
    let config: Config = serde_json::from_slice(&fs::read(config)?)?;
    version(&config.version)?;
    anyhow::ensure!(repository(&config.repository), "Invalid release repository");
    let signing = SigningKey::from_slice(&fs::read(config.private_key)?)?;
    anyhow::ensure!(
        signing.verifying_key().to_encoded_point(false).as_bytes()
            == STANDARD.decode(update_key::PUBLIC_KEY)?,
        "Signing key does not match this project's public key"
    );
    let bytes = fs::read(config.binary)?;
    let mut release = Release {
        version: config.version,
        arch: config.arch,
        size: bytes.len(),
        sha256: Sha256::digest(&bytes)
            .iter()
            .map(|v| format!("{v:02x}"))
            .collect(),
        url: String::new(),
    };
    release.url = release_url(&config.repository, &release);
    verify_binary(&bytes, &release)?;
    let payload = serde_json::to_vec(&release)?;
    let signature: Signature = signing.sign(&payload);
    let envelope = Envelope {
        payload: STANDARD.encode(&payload),
        signature: STANDARD.encode(signature.to_der().as_bytes()),
    };
    let manifest = serde_json::to_vec(&envelope)?;
    verify_feed(
        &manifest,
        signing.verifying_key(),
        &config.repository,
        &release.arch,
    )?;
    let binary = output.join(asset(&release.arch));
    private::save(&binary, &bytes)?;
    fs::set_permissions(binary, fs::Permissions::from_mode(0o755))?;
    private::save(
        &output.join(format!("manifest-macos-{}.json", release.arch)),
        &manifest,
    )?;
    println!("Release artifact and signed manifest generated; private key not exported.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (SigningKey, Release, Vec<u8>) {
        let key = SigningKey::from_slice(&[7; 32]).unwrap();
        let mut binary = vec![0; 64];
        binary[..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
        binary[4..8].copy_from_slice(&0x01000007u32.to_le_bytes());
        binary[12..16].copy_from_slice(&2u32.to_le_bytes());
        let mut release = Release {
            version: "1.2.3".into(),
            arch: "x86_64".into(),
            size: binary.len(),
            sha256: Sha256::digest(&binary)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
            url: String::new(),
        };
        release.url = release_url("example/clipboard", &release);
        (key, release, binary)
    }
    fn signed(key: &SigningKey, release: &Release) -> Vec<u8> {
        let payload = serde_json::to_vec(release).unwrap();
        let sig: Signature = key.sign(&payload);
        serde_json::to_vec(&Envelope {
            payload: STANDARD.encode(payload),
            signature: STANDARD.encode(sig.to_der().as_bytes()),
        })
        .unwrap()
    }
    #[test]
    fn signatures_reject_tampered_metadata_and_wrong_keys() {
        let (key, release, _) = fixture();
        let good = signed(&key, &release);
        assert!(verify_feed(&good, key.verifying_key(), "example/clipboard", "x86_64").is_ok());
        let mut envelope: Envelope = serde_json::from_slice(&good).unwrap();
        let mut bytes = STANDARD.decode(&envelope.payload).unwrap();
        bytes[0] ^= 1;
        envelope.payload = STANDARD.encode(bytes);
        assert!(
            verify_feed(
                &serde_json::to_vec(&envelope).unwrap(),
                key.verifying_key(),
                "example/clipboard",
                "x86_64"
            )
            .is_err()
        );
        let wrong = SigningKey::from_slice(&[8; 32]).unwrap();
        assert!(verify_feed(&good, wrong.verifying_key(), "example/clipboard", "x86_64").is_err());
    }
    #[test]
    fn reject_artifact_tampering_architecture_and_external_urls() {
        let (key, mut release, mut bytes) = fixture();
        assert!(verify_binary(&bytes, &release).is_ok());
        bytes[63] ^= 1;
        assert!(verify_binary(&bytes, &release).is_err());
        assert!(
            verify_feed(
                &signed(&key, &release),
                key.verifying_key(),
                "example/clipboard",
                "aarch64"
            )
            .is_err()
        );
        release.url = "https://example.com/malicious".into();
        assert!(
            verify_feed(
                &signed(&key, &release),
                key.verifying_key(),
                "example/clipboard",
                "x86_64"
            )
            .is_err()
        );
    }
    #[test]
    fn versions_are_numeric_and_stable_only() {
        assert!(version("1.10.0").unwrap() > version("1.9.99").unwrap());
        for bad in ["v1.2.3", "1.2", "1.2.3-beta", "01.2.3", "1.2.3.4", "1/2/3"] {
            assert!(version(bad).is_err());
        }
        assert!(!repository("../.."));
        assert!(!repository("a/b/c"));
    }

    #[test]
    fn failed_launch_restores_original_executable() {
        let (_, release, bytes) = fixture();
        let root = std::env::temp_dir().join(format!(
            "miclip-update-{:016x}",
            u64::from_ne_bytes(private::random().unwrap())
        ));
        fs::create_dir(&root).unwrap();
        let root = root.canonicalize().unwrap();
        let target = root.join("mi-clip");
        let staged = root.join("staged");
        fs::write(&target, b"original executable fixture").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).unwrap();
        private::save(&staged, &bytes).unwrap();
        assert!(
            install(
                PendingUpdate {
                    release,
                    staged,
                    executable: target.clone()
                },
                &[]
            )
            .is_err()
        );
        assert_eq!(fs::read(target).unwrap(), b"original executable fixture");
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    #[ignore = "requires MICLIP_TEST_APP pointing at a freshly built GUI executable"]
    fn real_gui_restart_reports_ready() {
        let binary =
            fs::read(std::env::var_os("MICLIP_TEST_APP").expect("built GUI path required"))
                .unwrap();
        let root = std::env::temp_dir().join(format!(
            "miclip-update-gui-{:016x}",
            u64::from_ne_bytes(private::random().unwrap())
        ));
        fs::create_dir(&root).unwrap();
        let root = root.canonicalize().unwrap();
        let target = root.join("mi-clip");
        let staged = root.join("staged");
        fs::write(&target, &binary).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).unwrap();
        private::save(&staged, &binary).unwrap();
        let release = Release {
            version: env!("CARGO_PKG_VERSION").into(),
            arch: std::env::consts::ARCH.into(),
            size: binary.len(),
            sha256: Sha256::digest(&binary)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
            url: String::new(),
        };
        install(
            PendingUpdate {
                release,
                staged,
                executable: target.clone(),
            },
            &["--smoke-test".into()],
        )
        .unwrap();
        assert_eq!(fs::read(target).unwrap(), binary);
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
        std::thread::sleep(std::time::Duration::from_secs(4));
        fs::remove_dir_all(root).unwrap();
    }
}
