//! Status item: one shared state machine with a native surface per platform.
//!
//! macOS draws an AppKit menu-bar item and a popup panel; Linux draws a
//! StatusNotifierItem and a normal window. Clipboard, discovery, update, and
//! file feedback events are handled once, in `run`.
use crate::Runtime;
use crate::devices::{Device, Devices};
use crate::ui::{self, Panel};
use async_channel::Sender;
use gpui_rhai::gpui::{App, WindowHandle};
use mi_clip::file_feedback::{Event as FileEvent, Feedback};
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
#[path = "tray/linux.rs"]
mod linux;
#[cfg(target_os = "macos")]
#[path = "tray/macos.rs"]
mod macos;

#[cfg(target_os = "macos")]
pub(crate) use macos::install;

/// macOS menu-bar anchor for the popup. Linux lets the compositor place windows.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
#[derive(Clone, Copy)]
pub(crate) struct Anchor {
    pub x: f32,
    pub y: f32,
}

pub(crate) enum TrayEvent {
    #[cfg(target_os = "macos")]
    Toggle(Anchor),
    Show,
    #[cfg(target_os = "linux")]
    Share(Vec<std::path::PathBuf>),
    TrayUnavailable,
    Quit,
    #[cfg(target_os = "macos")]
    Close,
    Status(&'static str, String),
    File(FileEvent),
    #[cfg(target_os = "macos")]
    AnimationTick,
    CheckUpdate,
    RefreshDevices,
    Discovering,
    Devices(Result<Vec<Device>, ()>),
    Connecting(std::net::SocketAddr),
    Update(crate::update_ui::Notice),
}

/// A status window ready to be mounted by the platform surface.
pub(crate) struct PanelInit {
    pub prepared: gpui_rhai::PreparedScriptView,
    pub events: Sender<TrayEvent>,
    pub update_text: String,
    pub status: &'static str,
    pub detail: String,
    pub devices: Devices,
}

/// Native parts of the status item. Only drawing and window placement differ.
pub(crate) trait Surface {
    fn render(&mut self, feedback: &Feedback, detail: &str) -> anyhow::Result<()>;

    fn open(
        &mut self,
        cx: &mut App,
        anchor: Option<Anchor>,
        panel: PanelInit,
    ) -> anyhow::Result<WindowHandle<Panel>>;

    /// Whether this surface animates status frames at all.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    fn animates(&self) -> bool {
        false
    }

    /// Opens the native share picker (Linux). Other platforms never request it.
    fn open_share(
        &mut self,
        _cx: &mut App,
        _files: &[std::path::PathBuf],
        _devices: Devices,
        _logged_in: bool,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    /// Pushes a new catalogue into an open share picker.
    fn refresh_share(&mut self, _cx: &mut App, _devices: Devices) {}
}

pub(crate) fn install(
    cx: &mut App,
    smoke: Option<std::rc::Rc<std::cell::Cell<bool>>>,
    config: Option<std::path::PathBuf>,
    runtime: Runtime,
) -> anyhow::Result<()> {
    #[cfg(target_os = "macos")]
    {
        macos::install(cx, smoke, config, runtime)
    }
    #[cfg(target_os = "linux")]
    {
        linux::install(cx, smoke, config, runtime)
    }
}

fn visible_detail(feedback: &Feedback, status_detail: &str) -> String {
    if status_detail.is_empty() {
        feedback.detail().unwrap_or_default()
    } else {
        status_detail.to_owned()
    }
}

#[cfg(target_os = "macos")]
fn schedule_frame(cx: &mut App, events: Sender<TrayEvent>, reduced_motion: bool) {
    cx.spawn(async move |cx| {
        cx.background_executor()
            .timer(if reduced_motion {
                Duration::from_secs(1)
            } else {
                Duration::from_millis(83)
            })
            .await;
        let _ = events.send(TrayEvent::AnimationTick).await;
    })
    .detach();
}

/// Shared event loop. `surface` owns every native object used to draw it.
#[allow(clippy::too_many_arguments)]
pub(crate) fn run(
    cx: &mut App,
    events: Sender<TrayEvent>,
    receiver: async_channel::Receiver<TrayEvent>,
    mut surface: impl Surface + 'static,
    runtime: Runtime,
    testing: bool,
    #[cfg_attr(not(target_os = "macos"), allow(unused_variables))] reduced_motion: bool,
    discovery_request: Option<std::sync::mpsc::SyncSender<()>>,
    update_request: Option<std::sync::mpsc::SyncSender<()>>,
) {
    let diagnostic_update = std::env::var_os("MICLIP_UPDATE_ROLLBACK").is_some();
    let event_sender = events;
    cx.spawn(async move |cx| {
        let clock = Instant::now();
        let mut feedback = Feedback::default();
        #[cfg(target_os = "macos")]
        let mut animation_pending = false;
        let mut last_notification: Option<Instant> = None;
        let mut panel: Option<WindowHandle<Panel>> = None;
        let mut devices = Devices::default();
        let mut status_text = "尚未连接";
        let mut detail_text = "请先完成设备登录".to_owned();
        let mut update_text = if diagnostic_update {
            "更新失败，重试".to_owned()
        } else {
            "检查更新".to_owned()
        };
        while let Ok(event) = receiver.recv().await {
            let result = cx.update(|cx| -> anyhow::Result<()> {
                let anchor = match event {
                    TrayEvent::Quit => {
                        cx.quit();
                        return Ok(());
                    }
                    #[cfg(target_os = "macos")]
                    TrayEvent::Close => {
                        if let Some(opened) = panel.take() {
                            let _ = opened.update(cx, |_, window, _| window.remove_window());
                        }
                        return Ok(());
                    }
                    TrayEvent::TrayUnavailable => {
                        // The status window stays usable without a tray host.
                        if let Some(opened) = panel.as_ref() {
                            let _ = opened.update(cx, |_, window, _| window.activate_window());
                        }
                        return Ok(());
                    }
                    #[cfg(target_os = "linux")]
                    TrayEvent::Share(files) => {
                        let logged_in = runtime.logged_in();
                        if let Err(error) =
                            surface.open_share(cx, &files, devices.clone(), logged_in)
                        {
                            eprintln!("Share window unavailable: {error}");
                            runtime.release_share();
                        }
                        if let Some(request) = &discovery_request {
                            let _ = request.try_send(());
                        }
                        return Ok(());
                    }
                    TrayEvent::RefreshDevices => {
                        if let Some(request) = &discovery_request {
                            let _ = request.try_send(());
                        }
                        return Ok(());
                    }
                    TrayEvent::Discovering => {
                        devices.scanning = true;
                        if let Some(opened) = panel.as_ref() {
                            let _ = opened
                                .update(cx, |panel, _, cx| panel.set_devices(devices.clone(), cx));
                        }
                        surface.refresh_share(cx, devices.clone());
                        return Ok(());
                    }
                    TrayEvent::Devices(result) => {
                        devices.scanning = false;
                        devices.failed = result.is_err();
                        if let Ok(entries) = result {
                            devices.entries = entries;
                            devices.updated = Some(Instant::now());
                        }
                        if let Some(opened) = panel.as_ref() {
                            let _ = opened
                                .update(cx, |panel, _, cx| panel.set_devices(devices.clone(), cx));
                        }
                        surface.refresh_share(cx, devices.clone());
                        return Ok(());
                    }
                    TrayEvent::Connecting(endpoint) => {
                        devices.target = Some(endpoint);
                        if let Some(opened) = panel.as_ref() {
                            let _ = opened
                                .update(cx, |panel, _, cx| panel.set_devices(devices.clone(), cx));
                        }
                        return Ok(());
                    }
                    TrayEvent::CheckUpdate => {
                        if std::env::var_os("MICLIP_UPDATE_DIAGNOSTICS").is_some() {
                            eprintln!("Mi Clip update: manual request received");
                        }
                        if runtime.update.lock().unwrap().is_some() {
                            runtime
                                .install_update
                                .store(true, std::sync::atomic::Ordering::Relaxed);
                            cx.quit();
                        } else if let Some(request) = &update_request {
                            update_text = match request.try_send(()) {
                                Ok(()) | Err(std::sync::mpsc::TrySendError::Full(())) => "检查中…",
                                Err(std::sync::mpsc::TrySendError::Disconnected(())) => {
                                    "检查服务已停止，请重启"
                                }
                            }
                            .into();
                        } else {
                            update_text = "检查服务未启动".into();
                        }
                        if let Some(opened) = panel.as_ref() {
                            let _ = opened
                                .update(cx, |panel, _, cx| panel.update_label(&update_text, cx));
                        }
                        return Ok(());
                    }
                    TrayEvent::Update(notice) => {
                        use crate::update_ui::Notice;
                        update_text = match notice {
                            Notice::Checking => "检查中…".into(),
                            Notice::Downloading(version) => format!("正在下载 v{version}…"),
                            Notice::Current => ui::current_version_label(),
                            Notice::Unpublished => "更新尚未发布".into(),
                            Notice::Failed => "检查失败 · 点击重试".into(),
                            Notice::NotInstallable => "请通过安装来源更新".into(),
                            Notice::Ready(update) => {
                                let text = format!("更新至 {}", update.version());
                                *runtime.update.lock().unwrap() = Some(update);
                                text
                            }
                        };
                        if std::env::var_os("MICLIP_UPDATE_DIAGNOSTICS").is_some() {
                            eprintln!("Mi Clip update state: {update_text}");
                        }
                        if let Some(opened) = panel.as_ref() {
                            let _ = opened
                                .update(cx, |panel, _, cx| panel.update_label(&update_text, cx));
                        }
                        return Ok(());
                    }
                    TrayEvent::Status(status, detail) => {
                        if std::env::var_os("MICLIP_DIAGNOSTICS").is_some() {
                            println!("Mi Clip state: {status}; {detail}");
                        }
                        status_text = status;
                        detail_text = detail;
                        let detail = visible_detail(&feedback, &detail_text);
                        surface.render(
                            &feedback,
                            &format!(
                                "{status}{}",
                                if detail.is_empty() {
                                    String::new()
                                } else {
                                    format!(" · {detail}")
                                }
                            ),
                        )?;
                        if let Some(opened) = panel.as_ref() {
                            let _ = opened.update(cx, |panel, window, cx| {
                                panel.refresh(status_text, &detail, window, cx)
                            });
                        }
                        return Ok(());
                    }
                    TrayEvent::File(event) => {
                        let changed = feedback.apply(event, clock.elapsed());
                        if changed {
                            detail_text.clear();
                        }
                        if changed && std::env::var_os("MICLIP_DIAGNOSTICS").is_some() {
                            if let Some(detail) = feedback.detail() {
                                println!("Mi Clip file state: {detail}");
                            }
                        }
                        if changed && !testing {
                            match event {
                                FileEvent::Requested
                                    if last_notification.is_none_or(|last| {
                                        last.elapsed() >= Duration::from_secs(15)
                                    }) =>
                                {
                                    last_notification = Some(Instant::now());
                                    crate::notifications::deliver(false);
                                }
                                FileEvent::Saved { .. } => crate::notifications::deliver(true),
                                _ => (),
                            }
                        }
                        let detail = visible_detail(&feedback, &detail_text);
                        surface.render(&feedback, &detail)?;
                        #[cfg(target_os = "macos")]
                        if surface.animates()
                            && feedback.appearance(clock.elapsed()).2
                            && (!reduced_motion || feedback.active())
                            && !animation_pending
                        {
                            animation_pending = true;
                            schedule_frame(cx, event_sender.clone(), reduced_motion);
                        }
                        if let Some(detail) = feedback.detail() {
                            if let Some(opened) = panel.as_ref() {
                                let _ = opened.update(cx, |panel, window, cx| {
                                    panel.refresh(status_text, &detail, window, cx)
                                });
                            }
                        }
                        return Ok(());
                    }
                    #[cfg(target_os = "macos")]
                    TrayEvent::AnimationTick => {
                        animation_pending = false;
                        let changed = feedback.tick(clock.elapsed());
                        if changed {
                            if let (Some(detail), Some(opened)) =
                                (feedback.detail(), panel.as_ref())
                            {
                                let _ = opened.update(cx, |panel, window, cx| {
                                    panel.refresh(status_text, &detail, window, cx)
                                });
                            }
                        }
                        let detail = visible_detail(&feedback, &detail_text);
                        surface.render(&feedback, &detail)?;
                        if surface.animates()
                            && feedback.appearance(clock.elapsed()).2
                            && (!reduced_motion || feedback.active())
                        {
                            animation_pending = true;
                            schedule_frame(cx, event_sender.clone(), reduced_motion);
                        }
                        return Ok(());
                    }
                    #[cfg(target_os = "macos")]
                    TrayEvent::Toggle(anchor) => Some(anchor),
                    TrayEvent::Show => {
                        if let Some(opened) = panel.as_ref() {
                            if opened
                                .update(cx, |_, window, _| window.activate_window())
                                .is_ok()
                            {
                                return Ok(());
                            }
                            panel = None;
                        }
                        None
                    }
                };
                if let Some(existing) = panel.take() {
                    if existing
                        .update(cx, |_, window, _| window.remove_window())
                        .is_ok()
                    {
                        return Ok(());
                    }
                }
                if let Some(request) = &discovery_request {
                    let _ = request.try_send(());
                }
                let detail = visible_detail(&feedback, &detail_text);
                // Rhai compilation and native window allocation happen only on demand.
                let prepared = ui::prepare_status(status_text, &detail)?;
                let opened = surface.open(
                    cx,
                    anchor,
                    PanelInit {
                        prepared,
                        events: event_sender.clone(),
                        update_text: update_text.clone(),
                        status: status_text,
                        detail,
                        devices: devices.clone(),
                    },
                )?;
                panel = Some(opened);
                // Acknowledge only once the user can actually see the window.
                feedback.acknowledge();
                let detail = visible_detail(&feedback, &detail_text);
                surface.render(&feedback, &detail)?;
                Ok(())
            });
            if let Err(error) = result {
                eprintln!("Panel unavailable: {error}");
            }
        }
    })
    .detach();
}
