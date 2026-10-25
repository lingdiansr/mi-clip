//! Register the bundled Share extension on first normal application launch.
//! Installation state belongs to this user, never to the build machine.
use std::{
    path::{Path, PathBuf},
    process::Command,
    sync::{
        OnceLock,
        atomic::{AtomicU8, Ordering},
    },
};

const IDENTIFIER: &str = "com.cyeam.miclip.share";
// 0: no containing app, 1: registering, 2: registered, 3: failed.
static STATE: AtomicU8 = AtomicU8::new(0);
static BUNDLE: OnceLock<Option<PathBuf>> = OnceLock::new();

fn containing_app(executable: &Path) -> Option<PathBuf> {
    let macos = executable.parent()?;
    if !macos.ends_with("Contents/MacOS") {
        return None;
    }
    let app = macos.parent()?.parent()?;
    app.extension().filter(|e| *e == "app")?;
    Some(app.to_path_buf())
}
fn bundle() -> Option<&'static Path> {
    BUNDLE
        .get_or_init(|| {
            std::env::current_exe()
                .ok()
                .and_then(|p| containing_app(&p))
        })
        .as_deref()
}
pub fn hint() -> &'static str {
    match STATE.load(Ordering::Relaxed) {
        1 => "正在注册 Clip 分享…",
        2 => "Clip 分享已注册 · 系统共享设置",
        3 => "Clip 分享注册失败 · 打开系统设置",
        _ => "安装 Clip.app 以启用系统共享 ↗",
    }
}
pub fn open_help() {
    let target = if bundle().is_some() {
        "x-apple.systempreferences:com.apple.LoginItems-Settings.extension"
    } else {
        "https://github.com/mnhkahn/mi-clip/releases/latest"
    };
    let _ = Command::new("/usr/bin/open").arg(target).spawn();
}
pub fn start() -> Option<std::thread::JoinHandle<()>> {
    let app = bundle()?;
    STATE.store(1, Ordering::Relaxed);
    Some(std::thread::spawn(move || {
        let result = setup(app);
        STATE.store(if result.is_ok() { 2 } else { 3 }, Ordering::Relaxed);
        if let Err(error) = result {
            eprintln!("Mi Clip Share setup failed: {error:#}");
        }
    }))
}
fn plugin_command(arguments: &[&std::ffi::OsStr]) -> anyhow::Result<()> {
    let output = Command::new("/usr/bin/pluginkit")
        .args(arguments)
        .output()?;
    anyhow::ensure!(
        output.status.success(),
        "Share extension registration command failed ({})",
        output.status
    );
    Ok(())
}
fn setup(app: &Path) -> anyhow::Result<()> {
    let extension = app.join("Contents/PlugIns/ClipShare.appex");
    anyhow::ensure!(
        extension.join("Contents/MacOS/ClipShare").is_file(),
        "Clip.app has no Share extension; reinstall the complete application"
    );
    use objc2_foundation::{NSString, NSURL};
    let path = app
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("Invalid application path"))?;
    let url = NSURL::fileURLWithPath(&NSString::from_str(path));
    // SAFETY: NSURL and CFURLRef are toll-free bridged; url stays retained for
    // this synchronous call. LaunchServices registers the containing bundle.
    let status = unsafe { LSRegisterURL((&*url as *const NSURL).cast(), 1) };
    anyhow::ensure!(
        status == 0,
        "Application registration failed (OSStatus {status})"
    );
    plugin_command(&["-a".as_ref(), extension.as_os_str()])?;
    let marker = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("Home directory unavailable"))?
        .join("Library/Application Support/MiClip/share-extension-enabled");
    enable_once(&marker, || {
        plugin_command(&[
            "-e".as_ref(),
            "use".as_ref(),
            "-i".as_ref(),
            IDENTIFIER.as_ref(),
        ])
    })
}
fn enable_once(marker: &Path, enable: impl FnOnce() -> anyhow::Result<()>) -> anyhow::Result<()> {
    // Enable at first installation only. Later starts and updates must preserve
    // a user's decision to disable the extension in System Settings.
    if marker.exists() {
        return Ok(());
    }
    enable()?;
    use std::{
        io::Write,
        os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    };
    let parent = marker
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Invalid setup marker"))?;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(parent)?;
    std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(marker)?
        .write_all(b"enabled-on-first-launch\n")?;
    Ok(())
}
#[link(name = "CoreServices", kind = "framework")]
unsafe extern "C" {
    fn LSRegisterURL(url: *const std::ffi::c_void, update: u8) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn first_install_enables_but_restart_preserves_user_disabled_choice() {
        let root = std::env::temp_dir().join(format!(
            "clip-setup-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let marker = root.join("enabled");
        assert!(enable_once(&marker, || anyhow::bail!("registration denied")).is_err());
        assert!(!marker.exists());
        enable_once(&marker, || Ok(())).unwrap();
        // Once the user has installed it, disabling it must survive a restart.
        enable_once(&marker, || panic!("must not override user preference")).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn standalone_binary_cannot_claim_to_contain_a_share_extension() {
        assert!(containing_app(Path::new("/usr/local/bin/mi-clip")).is_none());
        assert!(containing_app(Path::new("/tmp/Contents/MacOS/mi-clip")).is_none());
        assert_eq!(
            containing_app(Path::new("/Applications/Clip.app/Contents/MacOS/mi-clip")),
            Some(PathBuf::from("/Applications/Clip.app"))
        );
    }
}
