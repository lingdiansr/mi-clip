//! Signed, bounded application and executable updates.
//!
//! macOS accepts a raw executable or an application archive; Linux accepts only
//! a raw ELF executable. The application-bundle tooling is not compiled on Linux.
#[cfg(target_os = "macos")]
#[path = "update_bundle.rs"]
mod bundle;
#[cfg(target_os = "macos")]
use bundle::app_root;

/// Linux never runs a macOS application bundle.
#[cfg(not(target_os = "macos"))]
fn app_root(_: &Path) -> Option<&Path> {
    None
}
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
    None => "mnhkahn/mi-clip",
};
const MAX_BINARY: usize = 64 * 1024 * 1024;
const MAX_APP: usize = 128 * 1024 * 1024;

#[derive(Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Artifact {
    /// Legacy macOS raw executable; the field is omitted for these feeds.
    #[default]
    Binary,
    AppZip,
    /// Linux raw ELF executable; always named explicitly in its manifest.
    LinuxBinary,
}
impl Artifact {
    /// Only the legacy macOS executable feeds omit the kind field.
    fn is_binary(&self) -> bool {
        *self == Self::Binary
    }
    fn limit(self) -> usize {
        if self == Self::AppZip {
            MAX_APP
        } else {
            MAX_BINARY
        }
    }
    fn manifest(self, arch: &str) -> String {
        match self {
            Self::Binary => format!("manifest-macos-{arch}.json"),
            Self::AppZip => format!("manifest-app-macos-{arch}.json"),
            Self::LinuxBinary => format!("manifest-linux-{arch}.json"),
        }
    }
    fn asset(self, arch: &str) -> String {
        match self {
            Self::Binary => asset(arch),
            Self::AppZip => format!("Clip-macos-{arch}.zip"),
            Self::LinuxBinary => format!("mi-clip-linux-{arch}"),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    payload: String,
    signature: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Release {
    #[serde(default, skip_serializing_if = "Artifact::is_binary")]
    kind: Artifact,
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
        release.kind.asset(&release.arch)
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
        (32..=release.kind.limit()).contains(&release.size)
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
        matches!(release.kind, Artifact::Binary | Artifact::LinuxBinary),
        "Expected an executable update"
    );
    // The digest covers the exact bytes that are validated below.
    verify_digest(bytes, release)?;
    match release.kind {
        Artifact::Binary => verify_macho(bytes, &release.arch),
        Artifact::LinuxBinary => verify_elf(bytes, &release.arch),
        Artifact::AppZip => unreachable!(),
    }
}
fn verify_digest(bytes: &[u8], release: &Release) -> anyhow::Result<()> {
    anyhow::ensure!(
        bytes.len() == release.size && bytes.len() <= release.kind.limit(),
        "Update length mismatch"
    );
    let digest: String = Sha256::digest(bytes)
        .iter()
        .map(|v| format!("{v:02x}"))
        .collect();
    anyhow::ensure!(digest == release.sha256, "Update digest mismatch");
    Ok(())
}
fn verify_macho(bytes: &[u8], arch: &str) -> anyhow::Result<()> {
    let cpu = match arch {
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

/// Accepts only a complete little-endian ELF64 executable with an entry point
/// inside an executable loadable segment.
fn verify_elf(bytes: &[u8], arch: &str) -> anyhow::Result<()> {
    const HEADER: usize = 64;
    const PROGRAM_HEADER: usize = 56;
    const PT_LOAD: u32 = 1;
    const PF_X: u32 = 1;
    let machine = match arch {
        "x86_64" => 62u16,
        "aarch64" => 183,
        _ => anyhow::bail!("Unsupported update architecture"),
    };
    anyhow::ensure!(
        bytes.len() >= HEADER
            && bytes.get(..4) == Some(b"\x7fELF".as_slice())
            // 64-bit, little endian, current version.
            && bytes[4] == 2
            && bytes[5] == 1
            && bytes[6] == 1,
        "Update is not a 64-bit little-endian ELF executable"
    );
    let word = |offset: usize| u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
    let dword = |offset: usize| {
        u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
    };
    let qword = |offset: usize| {
        u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
    };
    // ET_EXEC or ET_DYN, matching machine and version.
    anyhow::ensure!(
        matches!(word(16), 2 | 3) && word(18) == machine && dword(20) == 1,
        "Update is not an executable for this architecture"
    );
    let entry = qword(24);
    let phoff = qword(32);
    let phentsize = u64::from(word(54));
    let phnum = u64::from(word(56));
    anyhow::ensure!(
        word(52) as u64 == HEADER as u64
            && phentsize == PROGRAM_HEADER as u64
            && phnum != 0
            && phoff >= HEADER as u64,
        "Update has an incomplete ELF header"
    );
    let table_end = phoff
        .checked_add(phnum.checked_mul(phentsize).ok_or_else(|| {
            anyhow::anyhow!("Update has an oversized ELF program header table")
        })?)
        .ok_or_else(|| anyhow::anyhow!("Update has an oversized ELF program header table"))?;
    anyhow::ensure!(
        table_end <= bytes.len() as u64,
        "Update has a truncated ELF program header table"
    );
    let mut entry_segment = false;
    for index in 0..phnum {
        let base = (phoff + index * phentsize) as usize;
        if dword(base) != PT_LOAD || dword(base + 4) & PF_X == 0 {
            continue;
        }
        let offset = qword(base + 8);
        let filesz = qword(base + 24);
        let memsz = qword(base + 32);
        anyhow::ensure!(
            offset
                .checked_add(filesz)
                .is_some_and(|end| end <= bytes.len() as u64),
            "Update has a truncated ELF segment"
        );
        let vaddr = qword(base + 16);
        if vaddr <= entry && entry < vaddr.saturating_add(memsz) {
            entry_segment = true;
        }
    }
    anyhow::ensure!(
        entry != 0 && entry_segment,
        "Update entry point is outside every executable ELF segment"
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
        let bytes = fs::read(&self.staged)?;
        match self.release.kind {
            Artifact::Binary | Artifact::LinuxBinary => verify_binary(&bytes, &self.release),
            Artifact::AppZip => {
                #[cfg(target_os = "macos")]
                {
                    bundle::verify_archive(&bytes, &self.release)
                }
                #[cfg(not(target_os = "macos"))]
                {
                    anyhow::bail!("Application archives are macOS-only")
                }
            }
        }
    }
}
impl Drop for PendingUpdate {
    fn drop(&mut self) {
        if matches!(self.release.kind, Artifact::Binary | Artifact::LinuxBinary) {
            let _ = fs::remove_file(&self.staged);
            return;
        }
        #[cfg(target_os = "macos")]
        bundle::cleanup(&self.staged);
    }
}
pub enum Check {
    Current,
    Unpublished,
    Ready(PendingUpdate),
}

/// Whether this installation may replace its own executable.
///
/// Package-managed locations are updated by their package manager, never by the
/// process itself; a standalone build in a user-writable directory may.
pub fn can_self_update() -> bool {
    std::env::current_exe().is_ok_and(|executable| self_update_allowed(&executable))
}

#[cfg(target_os = "macos")]
fn self_update_allowed(_: &Path) -> bool {
    true
}

/// Only a user-owned regular executable in a writable, non-managed directory.
#[cfg(target_os = "linux")]
fn self_update_allowed(executable: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;

    let Ok(metadata) = fs::metadata(executable) else {
        return false;
    };
    let uid = unsafe { libc::getuid() };
    if !metadata.is_file() || metadata.uid() != uid {
        return false;
    }
    let Some(parent) = executable.parent() else {
        return false;
    };
    let Ok(parent_metadata) = fs::metadata(parent) else {
        return false;
    };
    if parent_metadata.uid() != uid {
        return false;
    }
    let Ok(c_path) = std::ffi::CString::new(parent.as_os_str().as_bytes()) else {
        return false;
    };
    if unsafe { libc::access(c_path.as_ptr(), libc::W_OK) } != 0 {
        return false;
    }
    let path = executable.to_string_lossy();
    !["/usr/", "/opt/", "/nix/store/"]
        .iter()
        .any(|prefix| path.starts_with(prefix))
}

pub fn bundled() -> bool {
    std::env::current_exe().is_ok_and(|path| app_root(&path).is_some())
}

/// The artifact kind this platform installs.
fn platform_kind(executable: &Path) -> Artifact {
    #[cfg(target_os = "macos")]
    {
        if app_root(executable).is_some() {
            Artifact::AppZip
        } else {
            Artifact::Binary
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = executable;
        Artifact::LinuxBinary
    }
}

/// The raw executable kind this platform signs.
fn platform_binary_kind() -> Artifact {
    #[cfg(target_os = "macos")]
    {
        Artifact::Binary
    }
    #[cfg(not(target_os = "macos"))]
    {
        Artifact::LinuxBinary
    }
}

pub fn check() -> anyhow::Result<Check> {
    check_with_progress(|_| {})
}

pub fn check_with_progress(mut downloading: impl FnMut(&str)) -> anyhow::Result<Check> {
    anyhow::ensure!(repository(REPOSITORY), "Update repository not configured");
    anyhow::ensure!(
        self_update_allowed(&std::env::current_exe()?),
        "此安装位置不支持自更新，请通过安装来源更新"
    );
    let arch = std::env::consts::ARCH;
    let executable = std::env::current_exe()?.canonicalize()?;
    let kind = platform_kind(&executable);
    let url = format!(
        "https://github.com/{REPOSITORY}/releases/latest/download/{}",
        kind.manifest(arch)
    );
    let response = http::download(&url, 65536)?;
    if response.status == 404 {
        // Old macOS releases only have executable manifests. They can establish
        // "current", but can never authorize an unsigned application archive.
        #[cfg(target_os = "macos")]
        if kind == Artifact::AppZip {
            let legacy = http::download(
                &format!(
                    "https://github.com/{REPOSITORY}/releases/latest/download/{}",
                    Artifact::Binary.manifest(arch)
                ),
                65536,
            )?;
            if legacy.status == 200 {
                let key = VerifyingKey::from_sec1_bytes(&STANDARD.decode(update_key::PUBLIC_KEY)?)?;
                let release = verify_feed(&legacy.body, &key, REPOSITORY, arch)?;
                anyhow::ensure!(release.kind == Artifact::Binary, "Wrong legacy update type");
                if version(&release.version)? <= version(env!("CARGO_PKG_VERSION"))? {
                    return Ok(Check::Current);
                }
            } else {
                anyhow::ensure!(legacy.status == 404, "Legacy update feed request failed");
            }
        }
        return Ok(Check::Unpublished);
    }
    anyhow::ensure!(response.status == 200, "Update feed request failed");
    let key = VerifyingKey::from_sec1_bytes(&STANDARD.decode(update_key::PUBLIC_KEY)?)?;
    let release = verify_feed(&response.body, &key, REPOSITORY, arch)?;
    anyhow::ensure!(release.kind == kind, "Update artifact type mismatch");
    if version(&release.version)? <= version(env!("CARGO_PKG_VERSION"))? {
        return Ok(Check::Current);
    }
    downloading(&release.version);
    let response = http::download(&release.url, release.size)?;
    anyhow::ensure!(response.status == 200, "Update download failed");
    #[cfg(target_os = "macos")]
    if kind == Artifact::AppZip {
        let staged = bundle::prepare(&response.body, &release, &executable)?;
        return Ok(Check::Ready(PendingUpdate {
            release,
            staged,
            executable,
        }));
    }
    verify_binary(&response.body, &release)?;
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
    let parent = app_root(executable)
        .and_then(|p| p.parent())
        .or_else(|| executable.parent());
    Ok(parent
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
        path.parent()
            == app_root(&executable)
                .and_then(|p| p.parent())
                .or_else(|| executable.parent())
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
pub fn install(pending: PendingUpdate, arguments: &[std::ffi::OsString]) -> anyhow::Result<()> {
    use std::process::{Command, Stdio};
    anyhow::ensure!(
        self_update_allowed(&pending.executable),
        "此安装位置不支持自更新，请通过安装来源更新"
    );
    #[cfg(target_os = "linux")]
    anyhow::ensure!(
        pending.release.kind == Artifact::LinuxBinary,
        "更新类型与当前平台不符"
    );
    #[cfg(target_os = "macos")]
    anyhow::ensure!(
        pending.release.kind != Artifact::LinuxBinary,
        "更新类型与当前平台不符"
    );
    #[cfg(target_os = "macos")]
    if pending.release.kind == Artifact::AppZip {
        return bundle::install(&pending, arguments);
    }
    anyhow::ensure!(
        app_root(&pending.executable).is_none(),
        "Executable updates cannot modify an application bundle"
    );
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
        #[serde(default)]
        app_archive: Option<PathBuf>,
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
    #[cfg(target_os = "linux")]
    anyhow::ensure!(
        config.app_archive.is_none(),
        "Linux releases have a single binary asset"
    );
    let mut artifacts = vec![(platform_binary_kind(), fs::read(&config.binary)?)];
    if let Some(path) = config.app_archive {
        artifacts.push((Artifact::AppZip, fs::read(path)?));
    }
    for (kind, bytes) in artifacts {
        let mut release = Release {
            kind,
            version: config.version.clone(),
            arch: config.arch.clone(),
            size: bytes.len(),
            sha256: Sha256::digest(&bytes)
                .iter()
                .map(|v| format!("{v:02x}"))
                .collect(),
            url: String::new(),
        };
        release.url = release_url(&config.repository, &release);
        match kind {
            Artifact::Binary | Artifact::LinuxBinary => verify_binary(&bytes, &release)?,
            Artifact::AppZip => {
                #[cfg(target_os = "macos")]
                bundle::verify_archive(&bytes, &release)?;
                #[cfg(not(target_os = "macos"))]
                anyhow::bail!("Application archives are macOS-only");
            }
        }
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
        let artifact = output.join(kind.asset(&release.arch));
        private::save(&artifact, &bytes)?;
        if matches!(kind, Artifact::Binary | Artifact::LinuxBinary) {
            fs::set_permissions(artifact, fs::Permissions::from_mode(0o755))?;
        }
        private::save(&output.join(kind.manifest(&release.arch)), &manifest)?;
    }
    println!("Release artifact and signed manifest generated; private key not exported.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    /// A minimal ELF64 executable: one executable PT_LOAD covering the entry.
    fn elf_fixture() -> Vec<u8> {
        const TOTAL: usize = 64 + 56;
        let mut bytes = vec![0u8; TOTAL];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2; // ELFCLASS64
        bytes[5] = 1; // little endian
        bytes[6] = 1; // EV_CURRENT
        bytes[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        bytes[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        bytes[24..32].copy_from_slice(&0x400600u64.to_le_bytes()); // inside the segment
        bytes[32..40].copy_from_slice(&64u64.to_le_bytes()); // phoff
        bytes[52..54].copy_from_slice(&64u16.to_le_bytes()); // ehsize
        bytes[54..56].copy_from_slice(&56u16.to_le_bytes()); // phentsize
        bytes[56..58].copy_from_slice(&1u16.to_le_bytes()); // phnum
        let program = 64;
        bytes[program..program + 4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
        bytes[program + 4..program + 8].copy_from_slice(&5u32.to_le_bytes()); // R|X
        bytes[program + 8..program + 16].copy_from_slice(&0u64.to_le_bytes());
        bytes[program + 16..program + 24]
            .copy_from_slice(&0x400000u64.to_le_bytes()); // vaddr
        bytes[program + 24..program + 32]
            .copy_from_slice(&(TOTAL as u64).to_le_bytes()); // filesz
        bytes[program + 32..program + 40]
            .copy_from_slice(&0x1000u64.to_le_bytes()); // memsz
        bytes[program + 40..program + 48]
            .copy_from_slice(&0x1000u64.to_le_bytes()); // align
        bytes
    }

    fn release_for(kind: Artifact, arch: &str, binary: &[u8]) -> Release {
        let mut release = Release {
            kind,
            version: "1.2.3".into(),
            arch: arch.into(),
            size: binary.len(),
            sha256: Sha256::digest(binary)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
            url: String::new(),
        };
        release.url = release_url("example/clipboard", &release);
        release
    }

    fn fixture() -> (SigningKey, Release, Vec<u8>) {
        let key = SigningKey::from_slice(&[7; 32]).unwrap();
        #[cfg(target_os = "macos")]
        let binary = {
            let mut binary = vec![0; 64];
            binary[..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
            binary[4..8].copy_from_slice(&0x01000007u32.to_le_bytes());
            binary[12..16].copy_from_slice(&2u32.to_le_bytes());
            binary
        };
        #[cfg(target_os = "linux")]
        let binary = elf_fixture();
        let release = release_for(platform_binary_kind(), "x86_64", &binary);
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
    fn signed_app_feed_binds_archive_type_url_and_digest_without_changing_legacy_feeds() {
        let (key, mut release, binary) = fixture();
        let serialized = serde_json::to_value(&release).unwrap();
        #[cfg(target_os = "macos")]
        assert!(serialized.get("kind").is_none());
        #[cfg(target_os = "linux")]
        assert_eq!(serialized["kind"], "linux_binary");
        release.kind = Artifact::AppZip;
        release.url = release_url("example/clipboard", &release);
        assert!(release.url.ends_with("/Clip-macos-x86_64.zip"));
        let signed_app = signed(&key, &release);
        let verified = verify_feed(
            &signed_app,
            key.verifying_key(),
            "example/clipboard",
            "x86_64",
        )
        .unwrap();
        assert!(verified.kind == Artifact::AppZip);
        assert!(verify_binary(&binary, &verified).is_err());
        let mut envelope: Envelope = serde_json::from_slice(&signed_app).unwrap();
        release.kind = Artifact::Binary;
        envelope.payload = STANDARD.encode(serde_json::to_vec(&release).unwrap());
        assert!(
            verify_feed(
                &serde_json::to_vec(&envelope).unwrap(),
                key.verifying_key(),
                "example/clipboard",
                "x86_64"
            )
            .is_err()
        );
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
            kind: platform_binary_kind(),
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

    #[test]
    fn linux_elf_updates_reject_mach_o_zip_truncation_and_other_architectures() {
        let elf = elf_fixture();
        let release = release_for(Artifact::LinuxBinary, "x86_64", &elf);
        assert!(verify_binary(&elf, &release).is_ok());
        // The same bytes under the legacy macOS kind are not a Mach-O image.
        let legacy = release_for(Artifact::Binary, "x86_64", &elf);
        assert!(verify_binary(&elf, &legacy).is_err());
        // Mach-O and ZIP payloads are refused for Linux manifests.
        let mut macho = elf.clone();
        macho[..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
        let macho_release = release_for(Artifact::LinuxBinary, "x86_64", &macho);
        assert!(verify_binary(&macho, &macho_release).is_err());
        let zip = b"PK\x03\x04not-an-executable";
        let zip_release = release_for(Artifact::LinuxBinary, "x86_64", zip);
        assert!(verify_binary(zip, &zip_release).is_err());
        // A truncated program header table or segment is rejected.
        let mut truncated = elf.clone();
        truncated.truncate(90);
        let truncated_release = release_for(Artifact::LinuxBinary, "x86_64", &truncated);
        assert!(verify_binary(&truncated, &truncated_release).is_err());
        // Wrong architecture in either the manifest or the ELF header.
        let aarch64 = release_for(Artifact::LinuxBinary, "aarch64", &elf);
        assert!(verify_binary(&elf, &aarch64).is_err());
        // A shared object has no entry point.
        let mut shared = elf.clone();
        shared[16..18].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN
        shared[24..32].copy_from_slice(&0u64.to_le_bytes());
        let shared_release = release_for(Artifact::LinuxBinary, "x86_64", &shared);
        assert!(verify_binary(&shared, &shared_release).is_err());
        // An entry outside every executable segment is refused.
        let mut outside = elf.clone();
        outside[24..32].copy_from_slice(&0x9000u64.to_le_bytes());
        let outside_release = release_for(Artifact::LinuxBinary, "x86_64", &outside);
        assert!(verify_binary(&outside, &outside_release).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn only_user_owned_standalone_executables_may_self_update() {
        let root = std::env::temp_dir().join(format!(
            "miclip-self-update-{:016x}",
            u64::from_ne_bytes(private::random().unwrap())
        ));
        fs::create_dir(&root).unwrap();
        let executable = root.join("mi-clip");
        fs::write(&executable, b"synthetic executable").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(self_update_allowed(&executable));
        // A directory, a managed prefix, and a foreign owner are refused.
        assert!(!self_update_allowed(&root));
        assert!(!self_update_allowed(Path::new("/usr/bin/true")));
        assert!(!self_update_allowed(Path::new("/usr/local/bin/mi-clip")));
        // An unwritable parent directory refuses replacement. Root always may
        // write, so this check only applies to unprivileged test runs.
        if unsafe { libc::getuid() } != 0 {
            fs::set_permissions(&root, fs::Permissions::from_mode(0o500)).unwrap();
            assert!(!self_update_allowed(&executable));
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        }
        fs::remove_dir_all(root).unwrap();
    }
}
