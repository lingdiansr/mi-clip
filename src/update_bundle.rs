//! An authenticated archive is staged outside the signed app, then exchanged as
//! a whole. No receipt, archive, or health marker is written inside Clip.app.
use super::{Artifact, PendingUpdate, Release, health_file, verify_digest, verify_macho};
use std::{
    collections::HashSet,
    fs,
    io::{Cursor, Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

const MAX_EXPANDED: u64 = 512 * 1024 * 1024;
const MAX_ENTRIES: usize = 4096;
const MAIN: &str = "Clip.app/Contents/MacOS/mi-clip";

pub(super) fn app_root(executable: &Path) -> Option<&Path> {
    let macos = executable.parent()?;
    let contents = macos.parent()?;
    let app = contents.parent()?;
    (macos.file_name()? == "MacOS"
        && contents.file_name()? == "Contents"
        && app.extension()? == "app")
        .then_some(app)
}

fn inspect(bytes: &[u8], release: &Release) -> anyhow::Result<()> {
    let mut zip = zip::ZipArchive::new(Cursor::new(bytes))?;
    anyhow::ensure!(
        (1..=MAX_ENTRIES).contains(&zip.len()),
        "Invalid app archive entry count"
    );
    let mut names = HashSet::new();
    let mut total = 0u64;
    for index in 0..zip.len() {
        let entry = zip.by_index(index)?;
        let name = entry.name();
        let path = Path::new(name);
        anyhow::ensure!(
            !name.contains(['\\', '\0'])
                && !path.is_absolute()
                && path.components().all(|c| matches!(c, Component::Normal(_))),
            "Unsafe app archive path"
        );
        let root = path.components().next();
        anyhow::ensure!(
            matches!(root, Some(Component::Normal(s)) if s == "Clip.app" || s == "__MACOSX"),
            "Unexpected app archive root"
        );
        anyhow::ensure!(
            names.insert(name.trim_end_matches('/').to_owned()),
            "Duplicate app archive entry"
        );
        let mode = entry.unix_mode().unwrap_or(0) & 0o170000;
        anyhow::ensure!(
            matches!(mode, 0 | 0o100000 | 0o040000),
            "App archive contains a link or special file"
        );
        total = total
            .checked_add(entry.size())
            .ok_or_else(|| anyhow::anyhow!("App archive size overflow"))?;
        anyhow::ensure!(
            total <= MAX_EXPANDED && entry.size() <= MAX_EXPANDED,
            "Expanded app archive too large"
        );
    }
    let mut main = zip.by_name(MAIN)?;
    let mut header = [0; 16];
    main.read_exact(&mut header)?;
    verify_macho(&header, &release.arch)?;
    Ok(())
}

pub(super) fn verify_archive(bytes: &[u8], release: &Release) -> anyhow::Result<()> {
    anyhow::ensure!(
        release.kind == Artifact::AppZip,
        "Expected an application archive"
    );
    verify_digest(bytes, release)?;
    inspect(bytes, release)
}

fn extract(bytes: &[u8], release: &Release, directory: &Path) -> anyhow::Result<PathBuf> {
    verify_archive(bytes, release)?;
    fs::DirBuilder::new().mode(0o700).create(directory)?;
    let mut zip = zip::ZipArchive::new(Cursor::new(bytes))?;
    for index in 0..zip.len() {
        let mut entry = zip.by_index(index)?;
        if entry.name().starts_with("__MACOSX/") || entry.name() == "__MACOSX" {
            continue;
        }
        let target = directory.join(entry.name());
        if entry.is_dir() {
            fs::create_dir_all(&target)?;
        } else {
            fs::create_dir_all(target.parent().unwrap())?;
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&target)?;
            // Bound actual output as well as the untrusted ZIP size fields.
            let expected = entry.size();
            let count = std::io::copy(&mut (&mut entry).take(expected + 1), &mut file)?;
            anyhow::ensure!(count == expected, "App archive entry length mismatch");
            file.flush()?;
            file.sync_all()?;
            let mode = entry.unix_mode().unwrap_or(0o644);
            fs::set_permissions(
                &target,
                fs::Permissions::from_mode(if mode & 0o111 != 0 { 0o755 } else { 0o644 }),
            )?;
        }
    }
    let app = directory.join("Clip.app");
    verify_app(&app, release)?;
    Ok(app)
}

fn plist(path: &Path, key: &str) -> anyhow::Result<String> {
    let output = Command::new("/usr/libexec/PlistBuddy")
        .args(["-c", &format!("Print :{key}")])
        .arg(path)
        .output()?;
    anyhow::ensure!(output.status.success(), "Missing application metadata");
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}
fn verify_app(app: &Path, release: &Release) -> anyhow::Result<()> {
    let contents = app.join("Contents");
    for (info, id, executable) in [
        (contents.join("Info.plist"), "com.cyeam.miclip", "mi-clip"),
        (
            contents.join("PlugIns/ClipShare.appex/Contents/Info.plist"),
            "com.cyeam.miclip.share",
            "ClipShare",
        ),
    ] {
        anyhow::ensure!(
            plist(&info, "CFBundleIdentifier")? == id
                && plist(&info, "CFBundleShortVersionString")? == release.version
                && plist(&info, "CFBundleVersion")? == release.version
                && plist(&info, "CFBundleExecutable")? == executable,
            "Application identity or version mismatch"
        );
    }
    for executable in [
        contents.join("MacOS/mi-clip"),
        contents.join("PlugIns/ClipShare.appex/Contents/MacOS/ClipShare"),
    ] {
        let mut header = [0; 16];
        fs::File::open(executable)?.read_exact(&mut header)?;
        verify_macho(&header, &release.arch)?;
    }
    anyhow::ensure!(
        Command::new("/usr/bin/codesign")
            .args(["--verify", "--deep", "--strict"])
            .arg(app)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?
            .success(),
        "Application code signature rejected"
    );
    Ok(())
}

pub(super) fn prepare(
    bytes: &[u8],
    release: &Release,
    executable: &Path,
) -> anyhow::Result<PathBuf> {
    verify_archive(bytes, release)?;
    let app =
        app_root(executable).ok_or_else(|| anyhow::anyhow!("Application directory unavailable"))?;
    let root = health_file(executable)?.with_extension("staging");
    // The work directory shares the destination volume for atomic rename.
    anyhow::ensure!(
        root.parent() == app.parent(),
        "Update staging volume mismatch"
    );
    fs::DirBuilder::new().mode(0o700).create(&root)?;
    let archive = root.join("update.zip");
    let result = (|| {
        crate::private::save(&archive, bytes)?;
        extract(bytes, release, &root.join("checked"))?;
        Ok(archive.clone())
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(root);
    }
    result
}

pub(super) fn cleanup(archive: &Path) {
    if let Some(root) = archive.parent() {
        // Never delete the recoverable old app if rollback itself failed.
        if !root.join("Previous.app").exists() {
            let _ = fs::remove_dir_all(root);
        }
    }
}

pub(super) fn install(pending: &PendingUpdate, arguments: &[String]) -> anyhow::Result<()> {
    let mut transaction_started = false;
    let result = (|| {
        pending.validate()?;
        let root = pending
            .staged
            .parent()
            .ok_or_else(|| anyhow::anyhow!("Missing update directory"))?;
        let destination = app_root(&pending.executable)
            .ok_or_else(|| anyhow::anyhow!("Missing installed application"))?;
        let installed = plist(
            &destination.join("Contents/Info.plist"),
            "CFBundleShortVersionString",
        )?;
        anyhow::ensure!(
            super::version(&pending.release.version)? > super::version(&installed)?,
            "Application update would not upgrade the installed version"
        );
        anyhow::ensure!(
            root.parent() == destination.parent(),
            "Update staging volume mismatch"
        );
        // Re-extract the authenticated ZIP: a changed preflight copy is never run.
        let candidate = extract(
            &fs::read(&pending.staged)?,
            &pending.release,
            &root.join("install"),
        )?;
        transaction_started = true;
        replace_and_launch(
            destination,
            &candidate,
            root,
            &pending.release.version,
            arguments,
            Duration::from_secs(15),
        )
    })();
    if result.is_err() && !transaction_started {
        restart_previous(&pending.executable, arguments);
    }
    result
}

#[cfg(target_os = "macos")]
fn exchange(first: &Path, second: &Path) -> anyhow::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    unsafe extern "C" {
        fn renamex_np(
            first: *const std::ffi::c_char,
            second: *const std::ffi::c_char,
            flags: u32,
        ) -> i32;
    }
    let first = std::ffi::CString::new(first.as_os_str().as_bytes())?;
    let second = std::ffi::CString::new(second.as_os_str().as_bytes())?;
    // macOS sys/stdio.h: RENAME_SWAP = 0x2. Both paths always remain present.
    if unsafe { renamex_np(first.as_ptr(), second.as_ptr(), 0x2) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}
#[cfg(not(target_os = "macos"))]
fn exchange(_: &Path, _: &Path) -> anyhow::Result<()> {
    anyhow::bail!("Application exchange requires macOS")
}

fn restart_previous(executable: &Path, arguments: &[String]) {
    let _ = Command::new(executable)
        .args(arguments)
        .env_remove("MICLIP_UPDATE_READY")
        .env("MICLIP_UPDATE_ROLLBACK", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
}

fn replace_and_launch(
    destination: &Path,
    candidate: &Path,
    root: &Path,
    version: &str,
    arguments: &[String],
    timeout: Duration,
) -> anyhow::Result<()> {
    let executable = destination.join("Contents/MacOS/mi-clip");
    let backup = root.join("Previous.app");
    let ready = health_file(&executable)?;
    if let Err(error) = fs::rename(candidate, &backup) {
        restart_previous(&executable, arguments);
        return Err(error.into());
    }
    if let Err(error) = exchange(destination, &backup) {
        let _ = fs::rename(&backup, candidate);
        restart_previous(&executable, arguments);
        return Err(error);
    }
    let result = (|| {
        let mut child = Command::new(&executable)
            .args(arguments)
            .env("MICLIP_UPDATE_READY", &ready)
            .env_remove("MICLIP_UPDATE_ROLLBACK")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if fs::read(&ready).ok().as_deref() == Some(version.as_bytes()) {
                return Ok(());
            }
            if child.try_wait()?.is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = child.kill();
        let _ = child.wait();
        anyhow::bail!("Updated application failed its startup health check")
    })();
    let _ = fs::remove_file(&ready);
    if let Err(error) = result {
        // On failure the original app and its extension are restored together.
        exchange(destination, &backup).map_err(|error| {
            anyhow::anyhow!(
                "Previous application retained at {}: {error}",
                backup.display()
            )
        })?;
        let _ = fs::remove_dir_all(&backup);
        restart_previous(&executable, arguments);
        return Err(error);
    }
    let _ = fs::remove_dir_all(backup);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use zip::write::SimpleFileOptions;

    fn archive(extra: Option<&str>, link: bool) -> (Release, Vec<u8>) {
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let mut header = [0u8; 64];
        header[..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
        header[4..8].copy_from_slice(&0x01000007u32.to_le_bytes());
        header[12..16].copy_from_slice(&2u32.to_le_bytes());
        writer
            .start_file(MAIN, SimpleFileOptions::default().unix_permissions(0o755))
            .unwrap();
        writer.write_all(&header).unwrap();
        if let Some(name) = extra {
            if link {
                writer
                    .add_symlink(name, "../../outside", SimpleFileOptions::default())
                    .unwrap();
            } else {
                writer
                    .start_file(name, SimpleFileOptions::default())
                    .unwrap();
                writer.write_all(b"fixture").unwrap();
            }
        }
        let bytes = writer.finish().unwrap().into_inner();
        let release = Release {
            kind: Artifact::AppZip,
            version: "1.2.3".into(),
            arch: "x86_64".into(),
            size: bytes.len(),
            sha256: format!("{:x}", Sha256::digest(&bytes)),
            url: String::new(),
        };
        (release, bytes)
    }
    fn directory() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "miclip bundle test {:x}",
            u64::from_ne_bytes(crate::private::random().unwrap())
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        path.canonicalize().unwrap()
    }
    fn fake_app(path: &Path, label: &str, script: &str) {
        fs::create_dir_all(path.join("Contents/MacOS")).unwrap();
        fs::create_dir_all(path.join("Contents/PlugIns/ClipShare.appex")).unwrap();
        fs::write(path.join("Contents/PlugIns/ClipShare.appex/fixture"), label).unwrap();
        fs::write(path.join("Contents/MacOS/mi-clip"), script).unwrap();
        fs::set_permissions(
            path.join("Contents/MacOS/mi-clip"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
    }
    #[test]
    fn archive_rejects_tampering_traversal_links_unknown_roots_and_wrong_architecture() {
        let (mut release, mut bytes) = archive(None, false);
        verify_archive(&bytes, &release).unwrap();
        release.arch = "aarch64".into();
        assert!(verify_archive(&bytes, &release).is_err());
        release.arch = "x86_64".into();
        bytes[40] ^= 1;
        assert!(verify_archive(&bytes, &release).is_err());
        for bad in [
            "../escape",
            "/tmp/escape",
            "Clip.app/../escape",
            "Other.app/file",
            "Clip.app\\escape",
        ] {
            let (release, bytes) = archive(Some(bad), false);
            assert!(verify_archive(&bytes, &release).is_err(), "accepted {bad}");
        }
        let (release, bytes) = archive(Some("Clip.app/link"), true);
        assert!(verify_archive(&bytes, &release).is_err());
    }
    #[test]
    fn archive_expansion_is_bounded_before_extracting() {
        let (mut release, mut bytes) = archive(None, false);
        let central = bytes.windows(4).position(|v| v == b"PK\x01\x02").unwrap();
        bytes[central + 24..central + 28]
            .copy_from_slice(&((MAX_EXPANDED + 1) as u32).to_le_bytes());
        release.sha256 = format!("{:x}", Sha256::digest(&bytes));
        assert!(verify_archive(&bytes, &release).is_err());
    }
    #[test]
    fn health_receipts_are_outside_signed_application() {
        let exe = Path::new("/Applications/Clip.app/Contents/MacOS/mi-clip");
        assert_eq!(app_root(exe).unwrap(), Path::new("/Applications/Clip.app"));
        assert_eq!(
            health_file(exe).unwrap().parent().unwrap(),
            Path::new("/Applications")
        );
        assert!(app_root(Path::new("/usr/local/bin/mi-clip")).is_none());
    }
    #[test]
    fn successful_restart_replaces_main_and_extension_together() {
        let root = directory();
        let target = root.join("Clip.app");
        let work = root.join("work");
        let candidate = work.join("candidate/Clip.app");
        fs::create_dir(&work).unwrap();
        fake_app(&target, "old extension", "#!/bin/sh\nexit 0\n");
        fake_app(
            &candidate,
            "new extension",
            "#!/bin/sh\nprintf %s 1.2.3 > \"$MICLIP_UPDATE_READY\"\n",
        );
        replace_and_launch(
            &target,
            &candidate,
            &work,
            "1.2.3",
            &[],
            Duration::from_secs(2),
        )
        .unwrap();
        assert_eq!(
            fs::read_to_string(target.join("Contents/PlugIns/ClipShare.appex/fixture")).unwrap(),
            "new extension"
        );
        assert!(!work.join("Previous.app").exists());
        assert!(!fs::read_dir(&root).unwrap().any(|v| {
            v.unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".mi-clip-health-")
        }));
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn failed_restart_restores_main_and_extension_and_relaunches_previous_app() {
        let root = directory();
        let target = root.join("Clip.app");
        let work = root.join("work");
        let candidate = work.join("candidate/Clip.app");
        fs::create_dir(&work).unwrap();
        fake_app(
            &target,
            "old extension",
            "#!/bin/sh\nprintf %s \"$MICLIP_UPDATE_ROLLBACK\" > \"$1\"\n",
        );
        let old = fs::read(target.join("Contents/MacOS/mi-clip")).unwrap();
        fake_app(&candidate, "broken extension", "#!/bin/sh\nexit 1\n");
        let resumed = root.join("resumed");
        assert!(
            replace_and_launch(
                &target,
                &candidate,
                &work,
                "1.2.3",
                &[resumed.to_string_lossy().into_owned()],
                Duration::from_secs(2)
            )
            .is_err()
        );
        assert_eq!(
            fs::read(target.join("Contents/MacOS/mi-clip")).unwrap(),
            old
        );
        assert_eq!(
            fs::read_to_string(target.join("Contents/PlugIns/ClipShare.appex/fixture")).unwrap(),
            "old extension"
        );
        let deadline = Instant::now() + Duration::from_secs(2);
        while !resumed.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(fs::read_to_string(resumed).unwrap(), "1");
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn cleanup_preserves_the_backup_when_rollback_cannot_finish() {
        let root = directory();
        fs::create_dir(root.join("Previous.app")).unwrap();
        fs::write(root.join("update.zip"), b"fixture").unwrap();
        cleanup(&root.join("update.zip"));
        assert!(root.join("Previous.app").exists());
        fs::remove_dir_all(root.join("Previous.app")).unwrap();
        cleanup(&root.join("update.zip"));
        assert!(!root.exists());
    }
    #[test]
    #[ignore = "requires MICLIP_TEST_BUNDLE_ZIP and MICLIP_TEST_BUNDLE_VERSION"]
    fn real_signed_app_archive_preflight_and_extension_tamper_detection() {
        let bytes = fs::read(std::env::var_os("MICLIP_TEST_BUNDLE_ZIP").unwrap()).unwrap();
        let release = Release {
            kind: Artifact::AppZip,
            version: std::env::var("MICLIP_TEST_BUNDLE_VERSION").unwrap(),
            arch: std::env::consts::ARCH.into(),
            size: bytes.len(),
            sha256: format!("{:x}", Sha256::digest(&bytes)),
            url: String::new(),
        };
        let root = directory();
        let exe = root.join("Clip.app/Contents/MacOS/mi-clip");
        let archive = prepare(&bytes, &release, &exe).unwrap();
        let app = archive.parent().unwrap().join("checked/Clip.app");
        verify_app(&app, &release).unwrap();
        let ext = app.join("Contents/PlugIns/ClipShare.appex/Contents/MacOS/ClipShare");
        let mut file = fs::OpenOptions::new().append(true).open(ext).unwrap();
        file.write_all(b"tamper").unwrap();
        assert!(verify_app(&app, &release).is_err());
        cleanup(&archive);
        fs::remove_dir_all(root).unwrap();
    }
}
