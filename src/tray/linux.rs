//! Linux surface: StatusNotifierItem, a normal status window, and the share
//! picker. The tray is optional; without a host the window still works.
use super::{PanelInit, Surface, TrayEvent, run};
use crate::Runtime;
use crate::devices::Devices;
use crate::share_ui::{ShareInit, ShareWindow};
use crate::ui::{self, Panel};
use async_channel::Sender;
use gpui_rhai::gpui::{
    App, AppContext, Bounds, TitlebarOptions, WindowBounds, WindowHandle, WindowKind,
    WindowOptions, point, px, size,
};
use ksni::blocking::{Handle, TrayMethods};
use mi_clip::file_feedback::{Feedback, Icon};
use std::{
    path::PathBuf,
    sync::{
        Arc, LazyLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

const APP_ID: &str = "com.cyeam.miclip";
const TRAY_ICON_SIZE: u32 = 32;
/// How often the background thread re-checks the StatusNotifier host.
const TRAY_PROBE: Duration = Duration::from_secs(3);

/// A colourised status icon, rendered once from the template SVG.
struct Icons {
    idle: ksni::Icon,
    active: ksni::Icon,
    saved: ksni::Icon,
    failed: ksni::Icon,
}
impl Icons {
    fn for_state(&self, icon: Icon) -> ksni::Icon {
        match icon {
            Icon::Idle => self.idle.clone(),
            Icon::Connecting | Icon::Receiving => self.active.clone(),
            Icon::Saved => self.saved.clone(),
            Icon::Failed => self.failed.clone(),
        }
    }
}
static ICONS: LazyLock<Icons> = LazyLock::new(|| Icons {
    idle: render_icon(0x9a, 0xa0, 0xa6),
    active: render_icon(0x4c, 0x8d, 0xff),
    saved: render_icon(0x35, 0xc7, 0x59),
    failed: render_icon(0xff, 0x9f, 0x0a),
});

/// Rasterises the template SVG and tints its alpha mask.
fn render_icon(red: u8, green: u8, blue: u8) -> ksni::Icon {
    let options = resvg::usvg::Options::default();
    let tree = match resvg::usvg::Tree::from_str(
        include_str!("../../assets/status-template.svg"),
        &options,
    ) {
        Ok(tree) => tree,
        Err(_) => {
            return ksni::Icon {
                width: 0,
                height: 0,
                data: Vec::new(),
            };
        }
    };
    let tree_size = tree.size();
    let scale = TRAY_ICON_SIZE as f32 / tree_size.width().max(1.0);
    let mut pixmap = match resvg::tiny_skia::Pixmap::new(TRAY_ICON_SIZE, TRAY_ICON_SIZE) {
        Some(pixmap) => pixmap,
        None => {
            return ksni::Icon {
                width: 0,
                height: 0,
                data: Vec::new(),
            };
        }
    };
    resvg::render(
        &tree,
        resvg::tiny_skia::Transform::from_scale(scale, scale),
        &mut pixmap.as_mut(),
    );
    // StatusNotifierItem wants ARGB32 in network byte order.
    let mut data = Vec::with_capacity((TRAY_ICON_SIZE * TRAY_ICON_SIZE * 4) as usize);
    for pixel in pixmap.pixels() {
        let alpha = pixel.alpha();
        data.extend_from_slice(&[alpha, red, green, blue]);
    }
    ksni::Icon {
        width: TRAY_ICON_SIZE as i32,
        height: TRAY_ICON_SIZE as i32,
        data,
    }
}

struct LinuxTray {
    events: Sender<TrayEvent>,
    icon: ksni::Icon,
    tooltip: String,
}
impl ksni::Tray for LinuxTray {
    fn id(&self) -> String {
        "mi-clip".into()
    }
    fn title(&self) -> String {
        "Mi Clip".into()
    }
    fn icon_pixmap(&self) -> Vec<ksni::Icon> {
        vec![self.icon.clone()]
    }
    fn tool_tip(&self) -> ksni::ToolTip {
        ksni::ToolTip {
            title: "Mi Clip".into(),
            description: self.tooltip.clone(),
            ..Default::default()
        }
    }
    fn activate(&mut self, _x: i32, _y: i32) {
        let _ = self.events.try_send(TrayEvent::Show);
    }
    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        vec![
            ksni::menu::StandardItem {
                label: "显示状态".into(),
                activate: Box::new(|tray: &mut Self| {
                    let _ = tray.events.try_send(TrayEvent::Show);
                }),
                ..Default::default()
            }
            .into(),
            ksni::MenuItem::Separator,
            ksni::menu::StandardItem {
                label: "退出".into(),
                activate: Box::new(|tray: &mut Self| {
                    let _ = tray.events.try_send(TrayEvent::Quit);
                }),
                ..Default::default()
            }
            .into(),
        ]
    }
    fn watcher_offline(&self, _reason: ksni::OfflineReason) -> bool {
        // Keep serving: the window path remains usable and the item can come back.
        let _ = self.events.try_send(TrayEvent::TrayUnavailable);
        true
    }
    fn watcher_online(&self) {
        let _ = self.events.try_send(TrayEvent::TrayUnavailable);
    }
}

struct LinuxSurface {
    events: Sender<TrayEvent>,
    updates: Option<std::sync::mpsc::Sender<(Icon, String)>>,
    current: Option<Icon>,
    share: Option<WindowHandle<ShareWindow>>,
    reservation: Arc<AtomicBool>,
}

impl Surface for LinuxSurface {
    fn render(&mut self, feedback: &Feedback, tooltip: &str) -> anyhow::Result<()> {
        let (icon, _, _) = feedback.appearance(Duration::ZERO);
        if self.current == Some(icon) {
            return Ok(());
        }
        self.current = Some(icon);
        if let Some(updates) = &self.updates {
            // The tray handle is driven on its own thread; never block the UI.
            let _ = updates.send((icon, tooltip.to_owned()));
        }
        Ok(())
    }

    fn open(
        &mut self,
        cx: &mut App,
        _anchor: Option<super::Anchor>,
        panel: PanelInit,
    ) -> anyhow::Result<WindowHandle<Panel>> {
        let PanelInit {
            prepared,
            events,
            update_text,
            status,
            detail,
            devices,
        } = panel;
        let size_ = ui::panel_size(&detail);
        let opened = cx.open_window(
            WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(Bounds::new(
                    point(px(0.0), px(0.0)),
                    size_,
                ))),
                titlebar: Some(TitlebarOptions {
                    title: Some("Mi Clip".into()),
                    appears_transparent: false,
                    traffic_light_position: None,
                }),
                kind: WindowKind::Normal,
                // Matches the desktop entry's basename so the compositor
                // associates both windows with one application.
                app_id: Some(APP_ID.into()),
                is_resizable: true,
                window_min_size: Some(size(px(280.0), px(200.0))),
                ..Default::default()
            },
            move |window, cx| {
                cx.new(|cx| Panel::new(prepared, events, update_text, status, &detail, window, cx))
            },
        )?;
        opened.update(cx, |panel, _, cx| panel.set_devices(devices.clone(), cx))?;
        Ok(opened)
    }

    fn open_share(
        &mut self,
        cx: &mut App,
        files: &[PathBuf],
        devices: Devices,
        logged_in: bool,
    ) -> anyhow::Result<()> {
        if self
            .share
            .as_ref()
            .is_some_and(|opened| opened.update(cx, |_, _, _| ()).is_ok())
        {
            return Ok(());
        }
        self.share = None;
        let init = ShareInit {
            files: files.to_vec(),
            events: self.events.clone(),
            reservation: self.reservation.clone(),
            logged_in,
        };
        let opened = cx.open_window(
            WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(Bounds::new(
                    point(px(0.0), px(0.0)),
                    size(px(360.0), px(420.0)),
                ))),
                titlebar: Some(TitlebarOptions {
                    title: Some("Mi Clip · 分享".into()),
                    appears_transparent: false,
                    traffic_light_position: None,
                }),
                kind: WindowKind::Normal,
                app_id: Some(APP_ID.into()),
                is_resizable: true,
                window_min_size: Some(size(px(320.0), px(320.0))),
                ..Default::default()
            },
            move |_window, cx| cx.new(|cx| ShareWindow::new(cx, init)),
        )?;
        opened.update(cx, |share, _, cx| share.set_devices(devices, cx))?;
        self.share = Some(opened);
        Ok(())
    }

    fn refresh_share(&mut self, cx: &mut App, devices: Devices) {
        if let Some(opened) = self.share.as_ref()
            && opened
                .update(cx, |share, _, cx| share.set_devices(devices, cx))
                .is_err()
        {
            self.share = None;
        }
    }
}

/// Applies icon updates on a dedicated thread so `Handle::update` never runs on
/// the UI thread.
fn icon_thread(handle: Handle<LinuxTray>) -> std::sync::mpsc::Sender<(Icon, String)> {
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("mi-clip-tray".into())
        .spawn(move || {
            while let Ok((icon, tooltip)) = receiver.recv() {
                let pixmap = ICONS.for_state(icon);
                let _ = handle.update(|tray| {
                    tray.icon = pixmap;
                    tray.tooltip = tooltip;
                });
            }
        })
        .ok();
    sender
}

/// Reports whether any StatusNotifier host is registered with the session.
fn host_registered() -> anyhow::Result<bool> {
    let connection = zbus::blocking::Connection::session()?;
    let bus = zbus::blocking::fdo::DBusProxy::new(&connection)?;
    let watcher: zbus::names::BusName = "org.kde.StatusNotifierWatcher".try_into()?;
    if !bus.name_has_owner(watcher)? {
        return Ok(false);
    }
    let proxy = zbus::blocking::Proxy::new(
        &connection,
        "org.kde.StatusNotifierWatcher",
        "/StatusNotifierWatcher",
        "org.kde.StatusNotifierWatcher",
    )?;
    let registered: bool = proxy.get_property("IsStatusNotifierHostRegistered")?;
    Ok(registered)
}

/// Keep the window path honest when no tray host exists: report unavailability
/// once per transition. ksni itself re-registers when the watcher returns.
fn spawn_tray_probe(events: Sender<TrayEvent>, stop: Arc<AtomicBool>) {
    std::thread::Builder::new()
        .name("mi-clip-tray-probe".into())
        .spawn(move || {
            let mut last: Option<bool> = None;
            while !stop.load(Ordering::Relaxed) {
                let available = host_registered().unwrap_or(false);
                if last != Some(available) {
                    last = Some(available);
                    if !available {
                        let _ = events.try_send(TrayEvent::TrayUnavailable);
                    }
                }
                std::thread::sleep(TRAY_PROBE);
            }
        })
        .ok();
}

pub(crate) fn install(
    cx: &mut App,
    smoke: Option<std::rc::Rc<std::cell::Cell<bool>>>,
    config: Option<std::path::PathBuf>,
    runtime: Runtime,
) -> anyhow::Result<()> {
    let (sender, receiver) = async_channel::bounded(32);
    runtime.remember_events(receiver.clone());
    let testing = smoke.is_some();
    let logged_in = config.is_some() && !testing;
    if let Some(config) = config {
        let handle = crate::worker::start(config, sender.clone(), runtime.stop.clone());
        runtime.remember_worker(handle);
    }
    runtime.set_logged_in(logged_in);
    let discovery_request = if testing {
        None
    } else {
        Some(crate::devices::start(sender.clone(), runtime.stop.clone()))
    };
    let update_request = Some(if smoke.is_none() {
        crate::update_ui::start(sender.clone(), runtime.stop.clone())
    } else {
        crate::update_ui::start_smoke(sender.clone(), runtime.stop.clone())
    });
    // Forward session-bus control requests into the same event pump.
    if let Some(requests) = runtime.take_control_requests() {
        let events = sender.clone();
        std::thread::Builder::new()
            .name("mi-clip-control".into())
            .spawn(move || {
                while let Ok(request) = requests.recv_blocking() {
                    let event = match request {
                        crate::linux_control::Request::Show => TrayEvent::Show,
                        crate::linux_control::Request::Share(paths) => TrayEvent::Share(paths),
                    };
                    if events.try_send(event).is_err() {
                        break;
                    }
                }
            })
            .ok();
    }
    let tray = LinuxTray {
        events: sender.clone(),
        icon: ICONS.idle.clone(),
        tooltip: "Mi Clip · 尚未连接".into(),
    };
    // Assume SNI is available so a missing host becomes a soft error and the
    // window remains a usable fallback instead of aborting startup.
    let tray = tray.assume_sni_available(true).spawn();
    let updates = match tray {
        Ok(handle) => Some(icon_thread(handle)),
        Err(error) => {
            eprintln!("Status tray unavailable: {error}");
            let _ = sender.try_send(TrayEvent::TrayUnavailable);
            None
        }
    };
    if !testing {
        spawn_tray_probe(sender.clone(), runtime.stop.clone());
    }
    // The control entry point and the window path are both initialised.
    mi_clip::updater::mark_ready()?;
    if std::env::var_os("MICLIP_DIAGNOSTICS").is_some() {
        println!("Mi Clip status window ready.");
    }
    if let Some(passed) = smoke {
        smoke_test(cx, &sender, passed);
    }
    if let Some(files) = runtime.take_pending_share() {
        let _ = sender.try_send(TrayEvent::Share(files));
    }
    if runtime.show_on_start() {
        let _ = sender.try_send(TrayEvent::Show);
    }
    let surface = LinuxSurface {
        events: sender.clone(),
        updates,
        current: None,
        share: None,
        reservation: runtime.share.clone(),
    };
    run(
        cx,
        sender,
        receiver,
        surface,
        runtime,
        testing,
        // No 12 fps animation: a static icon per state is enough.
        true,
        discovery_request,
        update_request,
    );
    Ok(())
}

/// Exercises the window path without an account, network, or tray host.
fn smoke_test(
    cx: &mut App,
    events: &Sender<TrayEvent>,
    passed: std::rc::Rc<std::cell::Cell<bool>>,
) {
    let test_events = events.clone();
    let quitting = std::rc::Rc::new(std::cell::Cell::new(false));
    let expected = quitting.clone();
    cx.on_app_quit(move |_| {
        if !expected.get() {
            eprintln!("Linux smoke test ended before the Quit path ran");
            std::process::exit(1);
        }
        passed.set(true);
        println!("PASS: status window, Rhai refresh, Escape close, reopen and Quit");
        std::future::ready(())
    })
    .detach();
    cx.spawn(async move |cx| {
        let result = async {
            cx.background_executor()
                .timer(Duration::from_millis(300))
                .await;
            cx.update(|cx| -> anyhow::Result<()> {
                anyhow::ensure!(cx.windows().is_empty(), "Unexpected startup window");
                Ok(())
            })?;
            test_events.try_send(TrayEvent::Show)?;
            cx.background_executor()
                .timer(Duration::from_millis(900))
                .await;
            cx.update(|cx| -> anyhow::Result<()> {
                anyhow::ensure!(cx.windows().len() == 1, "Show did not open one window");
                let handle = cx.windows()[0]
                    .downcast::<Panel>()
                    .ok_or_else(|| anyhow::anyhow!("Wrong window root"))?;
                handle.update(cx, |panel, window, cx| -> anyhow::Result<()> {
                    panel.validate(cx)?;
                    panel.refresh("已连接", "冒烟测试状态", window, cx)?;
                    Ok(())
                })??;
                Ok(())
            })?;
            cx.background_executor()
                .timer(Duration::from_millis(400))
                .await;
            cx.update(|cx| -> anyhow::Result<()> {
                let handle = cx.windows()[0]
                    .downcast::<Panel>()
                    .ok_or_else(|| anyhow::anyhow!("Window disappeared"))?;
                cx.update_window(handle.into(), |_, window, cx| -> anyhow::Result<()> {
                    window.draw(cx).clear(cx);
                    window.dispatch_keystroke(gpui_rhai::gpui::Keystroke::parse("escape")?, cx);
                    Ok(())
                })??;
                Ok(())
            })?;
            cx.background_executor()
                .timer(Duration::from_millis(400))
                .await;
            cx.update(|cx| -> anyhow::Result<()> {
                anyhow::ensure!(cx.windows().is_empty(), "Escape did not close the window");
                Ok(())
            })?;
            println!("SMOKE CHECKPOINT: status window reopens");
            test_events.try_send(TrayEvent::Show)?;
            cx.background_executor()
                .timer(Duration::from_millis(900))
                .await;
            cx.update(|cx| -> anyhow::Result<()> {
                anyhow::ensure!(cx.windows().len() == 1, "Show did not reopen the window");
                Ok(())
            })?;
            // Route a real Ctrl-Q keystroke through the application bindings.
            quitting.set(true);
            cx.update(|cx| -> anyhow::Result<()> {
                let handle = cx.windows()[0]
                    .downcast::<Panel>()
                    .ok_or_else(|| anyhow::anyhow!("Window disappeared before Ctrl-Q"))?;
                cx.update_window(handle.into(), |_, window, cx| -> anyhow::Result<()> {
                    window.draw(cx).clear(cx);
                    window.dispatch_keystroke(gpui_rhai::gpui::Keystroke::parse("ctrl-q")?, cx);
                    Ok(())
                })??;
                Ok(())
            })?;
            Ok::<(), anyhow::Error>(())
        }
        .await;
        if let Err(error) = result {
            eprintln!("Linux smoke test failed: {error}");
            std::process::exit(1);
        }
    })
    .detach();
}
