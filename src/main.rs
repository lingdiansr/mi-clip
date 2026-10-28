#![deny(unsafe_op_in_unsafe_fn)]
mod devices;
#[cfg(target_os = "linux")]
mod linux_control;
mod notifications;
mod probe;
#[cfg(target_os = "linux")]
mod share_ui;
#[cfg(target_os = "macos")]
mod sharing_setup;
mod tray;
mod ui;
mod update_ui;
mod worker;

use std::{
    ffi::OsString,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

/// State shared between the platform surface and the shutdown path.
#[derive(Clone, Default)]
pub(crate) struct Runtime {
    stop: Arc<AtomicBool>,
    update: Arc<Mutex<Option<mi_clip::updater::PendingUpdate>>>,
    install_update: Arc<AtomicBool>,
    #[cfg(target_os = "linux")]
    share: Arc<AtomicBool>,
    #[cfg(target_os = "linux")]
    logged_in: Arc<AtomicBool>,
    #[cfg(target_os = "linux")]
    pending_share: Arc<Mutex<Option<Vec<PathBuf>>>>,
    #[cfg(target_os = "linux")]
    show: Arc<AtomicBool>,
    #[cfg(target_os = "linux")]
    control: Arc<Mutex<Option<linux_control::Control>>>,
    #[cfg(target_os = "linux")]
    events: Arc<Mutex<Option<async_channel::Receiver<tray::TrayEvent>>>>,
    #[cfg(target_os = "linux")]
    worker: Arc<Mutex<Option<std::thread::JoinHandle<()>>>>,
}

#[cfg(target_os = "linux")]
impl Runtime {
    pub(crate) fn remember_events(&self, receiver: async_channel::Receiver<tray::TrayEvent>) {
        *self.events.lock().unwrap() = Some(receiver);
    }

    pub(crate) fn remember_worker(&self, handle: std::thread::JoinHandle<()>) {
        *self.worker.lock().unwrap() = Some(handle);
    }

    pub(crate) fn set_logged_in(&self, value: bool) {
        self.logged_in.store(value, Ordering::SeqCst);
    }

    pub(crate) fn logged_in(&self) -> bool {
        self.logged_in.load(Ordering::SeqCst)
    }

    pub(crate) fn release_share(&self) {
        self.share.store(false, Ordering::SeqCst);
    }

    pub(crate) fn take_control_requests(
        &self,
    ) -> Option<async_channel::Receiver<linux_control::Request>> {
        self.control
            .lock()
            .unwrap()
            .as_mut()
            .and_then(|control| control.take_requests())
    }

    pub(crate) fn take_pending_share(&self) -> Option<Vec<PathBuf>> {
        self.pending_share.lock().unwrap().take()
    }

    pub(crate) fn show_on_start(&self) -> bool {
        self.show.swap(false, Ordering::SeqCst)
    }

    /// Stops background work and gives up the session bus name so a replacement
    /// process can take over.
    fn shutdown_background(&self) {
        self.stop.store(true, Ordering::Relaxed);
        // Closing the channel wakes a worker blocked in send_blocking.
        if let Some(events) = self.events.lock().unwrap().take() {
            events.close();
        }
        if let Some(worker) = self.worker.lock().unwrap().take() {
            let _ = worker.join();
        }
        if let Some(control) = self.control.lock().unwrap().take() {
            control.release();
        }
    }
}

#[derive(Default)]
struct Options {
    config: Option<PathBuf>,
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    share: Vec<PathBuf>,
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    background: bool,
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    show: bool,
    smoke: bool,
}

use gpui_rhai::gpui;
use gpui_rhai::gpui::{App, KeyBinding, QuitMode, actions};
actions!(mi_clip, [ClosePanel, Quit]);

fn main() -> anyhow::Result<()> {
    let arguments: Vec<OsString> = std::env::args_os().skip(1).collect();
    let only =
        |value: &str| matches!(arguments.as_slice(), [single] if single.to_str() == Some(value));
    if only("--version") {
        println!("Mi Clip {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if only("--check-update") {
        println!(
            "Mi Clip {} · {}",
            env!("CARGO_PKG_VERSION"),
            mi_clip::updater::REPOSITORY
        );
        if !mi_clip::updater::can_self_update() {
            println!("此安装位置不支持自更新，请通过安装来源更新。");
            return Ok(());
        }
        match mi_clip::updater::check()? {
            mi_clip::updater::Check::Current => println!("已是最新版本"),
            mi_clip::updater::Check::Unpublished => println!("更新尚未发布"),
            mi_clip::updater::Check::Ready(update) => println!(
                "发现并验证更新 {}；打开状态面板重新检查并安装。",
                update.version()
            ),
        }
        return Ok(());
    }
    if arguments.first().and_then(|value| value.to_str()) == Some("--auth") {
        return mi_clip::auth_cli::run(&utf8_arguments(&arguments[1..])?);
    }
    if arguments.len() == 3 && arguments[0].to_str() == Some("--probe") {
        let rest = utf8_arguments(&arguments[1..])?;
        return probe::run(&rest[0], rest[1].parse()?);
    }
    if only("--check-ui") {
        ui::prepare()?;
        println!("UI scripts validated; no window created.");
        return Ok(());
    }
    if only("--help") || only("-h") {
        help();
        return Ok(());
    }
    let options = parse(&arguments)?;
    let smoke = options.smoke;
    // Never let the UI framework silently fall back to X11 or a headless mode.
    #[cfg(target_os = "linux")]
    ensure_wayland_gui()?;
    let config = match options.config.clone() {
        Some(path) => Some(path),
        None => {
            let default = mi_clip::paths::default_config()?;
            default.is_file().then_some(default)
        }
    };
    let config = if smoke { None } else { config };
    if options.share.is_empty() {
        // No picker requested.
    } else {
        anyhow::ensure!(
            config.is_some() && !smoke,
            "请先完成设备登录，再选择要分享的文件"
        );
        anyhow::ensure!(!options.share.is_empty(), "没有可分享的文件");
    }
    // An installed app registers its macOS extension even when an older
    // standalone client already owns the clipboard lock.
    #[cfg(target_os = "macos")]
    let share_setup = if smoke { None } else { sharing_setup::start() };
    let runtime = Runtime::default();
    // Linux uses the session bus as its single-instance entry point and forwards
    // requests to the running instance; macOS keeps its file lock.
    #[cfg(target_os = "linux")]
    {
        let show_request = options.show || (!options.background && options.share.is_empty());
        if !smoke {
            match linux_control::session(
                show_request,
                &options.share,
                options.config.is_some(),
                runtime.share.clone(),
            )? {
                Some(control) => *runtime.control.lock().unwrap() = Some(control),
                None => return Ok(()),
            }
        }
        if !options.share.is_empty() {
            // Validate and normalise before taking the reservation.
            let uris = linux_control::encode_paths(&options.share)?;
            let files = linux_control::validate_uris(&uris)?;
            anyhow::ensure!(
                runtime
                    .share
                    .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok(),
                "已有文件分享任务在进行中"
            );
            *runtime.pending_share.lock().unwrap() = Some(files);
        }
        if !smoke {
            runtime.show.store(show_request, Ordering::SeqCst);
        }
    }
    #[cfg(target_os = "macos")]
    let _instance = if !smoke {
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
        let directory = mi_clip::paths::config_dir()?;
        mi_clip::paths::ensure_private_dir(&directory)?;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(directory.join("instance.lock"))?;
        if file.try_lock().is_err() {
            if let Some(setup) = share_setup {
                let _ = setup.join();
            }
            return Ok(());
        }
        Some(file)
    } else {
        None
    };
    if !smoke && let Ok(directory) = mi_clip::paths::state_dir() {
        mi_clip::analytics::start(directory);
    }
    let restart_args = restart_arguments(&options, &arguments);
    let passed = std::rc::Rc::new(std::cell::Cell::new(false));
    let signal = passed.clone();
    let background = runtime.clone();
    gpui_rhai::gpui_platform::application()
        .with_quit_mode(QuitMode::Explicit)
        .run(move |cx: &mut App| {
            gpui_rhai::install(cx);
            let quitting = background.clone();
            // AppKit termination exits the process; code after application.run
            // is not a shutdown hook on macOS. Finish replacement here, before
            // returning control to the native termination callback.
            #[cfg(target_os = "macos")]
            let mut instance = _instance;
            cx.on_app_quit(move |_| {
                quitting.stop.store(true, Ordering::Relaxed);
                #[cfg(target_os = "linux")]
                quitting.shutdown_background();
                #[cfg(target_os = "macos")]
                drop(instance.take());
                mi_clip::analytics::shutdown();
                if quitting.install_update.load(Ordering::Relaxed) {
                    if let Some(update) = quitting.update.lock().unwrap().take() {
                        if let Err(error) = mi_clip::updater::install(update, &restart_args) {
                            eprintln!("Mi Clip update installation failed: {error:#}");
                        }
                    }
                }
                // Native termination does not run Rust destructors: remove a
                // downloaded update even when the user chooses plain Quit.
                drop(quitting.update.lock().unwrap().take());
                std::future::ready(())
            })
            .detach();
            #[cfg(target_os = "macos")]
            cx.bind_keys([
                KeyBinding::new("escape", ClosePanel, None),
                KeyBinding::new("cmd-q", Quit, None),
            ]);
            #[cfg(target_os = "linux")]
            cx.bind_keys([
                KeyBinding::new("escape", ClosePanel, None),
                KeyBinding::new("ctrl-q", Quit, None),
            ]);
            cx.on_action(|_: &Quit, cx| cx.quit());
            if let Err(error) = tray::install(cx, smoke.then_some(signal), config, background) {
                eprintln!("Status item failed: {error}");
                cx.quit();
            }
        });
    anyhow::ensure!(!smoke || passed.get(), "Status panel smoke test failed");
    Ok(())
}

fn utf8_arguments(arguments: &[OsString]) -> anyhow::Result<Vec<String>> {
    arguments
        .iter()
        .map(|value| {
            value
                .to_str()
                .map(str::to_owned)
                .ok_or_else(|| anyhow::anyhow!("Arguments must be valid UTF-8"))
        })
        .collect()
}

fn parse(arguments: &[OsString]) -> anyhow::Result<Options> {
    let mut options = Options::default();
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index].to_str() {
            Some("--config") => {
                let value = arguments
                    .get(index + 1)
                    .ok_or_else(|| anyhow::anyhow!("--config 需要路径"))?;
                anyhow::ensure!(options.config.is_none(), "--config 只能指定一次");
                options.config = Some(PathBuf::from(value));
                index += 2;
            }
            #[cfg(target_os = "linux")]
            Some("--share") => {
                index += 1;
                if arguments.get(index).is_some_and(|value| value == "--") {
                    index += 1;
                }
                while index < arguments.len() {
                    options.share.push(PathBuf::from(&arguments[index]));
                    index += 1;
                }
            }
            #[cfg(target_os = "linux")]
            Some("--background") => {
                options.background = true;
                index += 1;
            }
            #[cfg(target_os = "linux")]
            Some("--show") => {
                options.show = true;
                index += 1;
            }
            Some("--smoke-test") => {
                options.smoke = true;
                index += 1;
            }
            _ => anyhow::bail!("Unknown argument; use --help"),
        }
    }
    #[cfg(target_os = "linux")]
    anyhow::ensure!(
        !(options.background && options.show),
        "--background 与 --show 不能同时使用"
    );
    Ok(options)
}

/// Arguments a replacement process receives after an update.
///
/// Linux keeps only the durable parts: background mode and an explicit
/// configuration path. One-shot actions such as `--share` or `--show` are never
/// replayed. macOS keeps its original command line.
fn restart_arguments(options: &Options, original: &[OsString]) -> Vec<OsString> {
    #[cfg(target_os = "macos")]
    {
        let _ = options;
        original.to_vec()
    }
    #[cfg(target_os = "linux")]
    {
        let _ = original;
        if options.smoke {
            return vec![OsString::from("--smoke-test")];
        }
        let mut arguments = vec![OsString::from("--background")];
        if let Some(config) = &options.config
            && let Ok(absolute) = std::path::absolute(config)
        {
            arguments.push(OsString::from("--config"));
            arguments.push(absolute.into_os_string());
        }
        arguments
    }
}

/// Refuses to start the GUI without a real Wayland session.
#[cfg(target_os = "linux")]
fn ensure_wayland_gui() -> anyhow::Result<()> {
    const MESSAGE: &str = "Linux 仅支持真实 Wayland 会话，请检查 WAYLAND_DISPLAY / ZED_HEADLESS";
    anyhow::ensure!(std::env::var_os("ZED_HEADLESS").is_none(), "{MESSAGE}");
    anyhow::ensure!(
        std::env::var_os("WAYLAND_DISPLAY").is_some_and(|value| !value.is_empty()),
        "{MESSAGE}"
    );
    anyhow::ensure!(gpui::guess_compositor() == "Wayland", "{MESSAGE}");
    wayland_client::Connection::connect_to_env()
        .map_err(|_| anyhow::anyhow!("{MESSAGE}：无法连接合成器"))?;
    Ok(())
}

fn help() {
    #[cfg(target_os = "macos")]
    let platform = "--config PATH: use a private account configuration\n--smoke-test: exercise the status popup lifecycle";
    #[cfg(target_os = "linux")]
    let platform = "--config PATH: use a private account configuration\n--background: start without opening the status window\n--show: show the status window\n--share FILE...: choose a phone for these files (also --share -- FILE...)\n--smoke-test: exercise the status window lifecycle";
    println!(
        "Mi Clip — standalone Xiaomi clipboard client\nClick the status icon or run without --background to see status.\n--version: print the current version\n--check-update: check and verify an update without installing\n--auth COMMAND INPUT OUTPUT: account setup and research CLI\n--check-ui: validate embedded Rhai scripts\n--probe HOST PORT: test device-info negotiation only\n{platform}\nSupports inline UTF-8 text up to 3 KiB, file clipboard offers, and native phone file sharing to ~/Downloads. No vendor runtime required."
    );
}
