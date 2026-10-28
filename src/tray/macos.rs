//! macOS menu-bar surface: NSStatusItem, popup panel, and vector icon frames.
use super::{Anchor, PanelInit, Surface, TrayEvent, run};
use crate::Runtime;
use crate::ui::{self, Panel};
use async_channel::Sender;
use gpui_rhai::gpui::{
    App, AppContext, Bounds, WindowBounds, WindowHandle, WindowKind, WindowOptions, point, px,
};
use mi_clip::file_feedback::{Event as FileEvent, Feedback, Icon};
use objc2::rc::Retained;
use objc2::{AnyThread, DefinedClass, MainThreadOnly, define_class, msg_send, sel};
use objc2_app_kit::{
    NSApplication, NSApplicationActivationPolicy, NSImage, NSScreen, NSStatusBar,
    NSStatusBarButton, NSStatusItem, NSWorkspace,
};
use objc2_foundation::{MainThreadMarker, NSData, NSObject, NSObjectProtocol, NSSize, ns_string};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

struct ActionState {
    events: Sender<TrayEvent>,
}
define_class!(
    #[unsafe(super = NSObject)]
    #[thread_kind = MainThreadOnly]
    #[ivars = ActionState]
    struct TrayAction;
    unsafe impl NSObjectProtocol for TrayAction {}
    impl TrayAction {
        #[unsafe(method(togglePanel:))]
        fn toggle_panel(&self, sender: &NSStatusBarButton) {
            if let Some(window) = sender.window() {
                let rect = window.frame();
                let screens = NSScreen::screens(self.mtm());
                let main_height = screens.firstObject().map(|s| s.frame().size.height).unwrap_or(0.0);
                let screen_left = window.screen().map(|s| s.frame().origin.x).unwrap_or(0.0);
                let anchor = Anchor {
                    x: ((rect.origin.x + rect.size.width - f64::from(ui::PANEL_WIDTH)).max(screen_left + 4.0)) as f32,
                    y: (main_height - rect.origin.y + 4.0) as f32,
                };
                // A bounded channel coalesces repeated clicks without timers or busy polling.
                let _ = self.ivars().events.try_send(TrayEvent::Toggle(anchor));
            }
        }
    }
);
impl TrayAction {
    fn new(mtm: MainThreadMarker, events: Sender<TrayEvent>) -> Retained<Self> {
        let this = Self::alloc(mtm).set_ivars(ActionState { events });
        // SAFETY: NSObject's initializer is valid for this subclass.
        unsafe { msg_send![super(this), init] }
    }
}

struct FileIcons {
    // Generated only when a file event first occurs. Frames remain vector PDFs.
    frames: Vec<(Icon, Vec<Retained<NSImage>>)>,
}
impl FileIcons {
    fn new() -> Self {
        Self { frames: Vec::new() }
    }
    fn image(&mut self, icon: Icon, frame: usize) -> anyhow::Result<&NSImage> {
        if !self.frames.iter().any(|(kind, _)| *kind == icon) {
            let count = if matches!(icon, Icon::Saved | Icon::Receiving) {
                12
            } else {
                1
            };
            let images = (0..count)
                .map(|frame| {
                    let pdf = mi_clip::file_feedback::icon_pdf(icon, frame);
                    let image = NSImage::initWithData(NSImage::alloc(), &NSData::with_bytes(&pdf))
                        .ok_or_else(|| anyhow::anyhow!("Invalid file feedback icon"))?;
                    image.setSize(NSSize::new(18., 18.));
                    image.setTemplate(false);
                    Ok(image)
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
            self.frames.push((icon, images));
        }
        let (_, images) = self.frames.iter().find(|(kind, _)| *kind == icon).unwrap();
        Ok(&images[frame % images.len()])
    }
}

struct StatusItem {
    item: Retained<NSStatusItem>,
    _action: Retained<TrayAction>,
    stop: Arc<AtomicBool>,
    button: Retained<NSStatusBarButton>,
    idle: Retained<NSImage>,
    icons: FileIcons,
    clock: Instant,
    reduced_motion: bool,
}

impl Surface for StatusItem {
    fn render(&mut self, feedback: &Feedback, tooltip: &str) -> anyhow::Result<()> {
        let (icon, mut frame, mut animated) = feedback.appearance(self.clock.elapsed());
        if self.reduced_motion {
            frame = 0;
            animated = false;
        }
        if icon == Icon::Idle {
            self.button.setImage(Some(&self.idle));
        } else {
            self.button.setImage(Some(self.icons.image(icon, frame)?));
        }
        let alpha = if animated && matches!(icon, Icon::Connecting | Icon::Failed) {
            0.75 + 0.25 * (frame as f64 * std::f64::consts::TAU / 12.).cos()
        } else {
            1.
        };
        self.button.setAlphaValue(alpha);
        if !tooltip.is_empty() {
            self.button
                .setToolTip(Some(&objc2_foundation::NSString::from_str(&format!(
                    "Mi Clip · {tooltip}"
                ))));
        }
        Ok(())
    }

    fn open(
        &mut self,
        cx: &mut App,
        anchor: Option<Anchor>,
        panel: PanelInit,
    ) -> anyhow::Result<WindowHandle<Panel>> {
        let anchor = anchor.unwrap_or(Anchor { x: 0.0, y: 0.0 });
        let PanelInit {
            prepared,
            events,
            update_text,
            status,
            detail,
            devices,
        } = panel;
        let size = ui::panel_size(&detail);
        let opened = cx.open_window(
            WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(Bounds::new(
                    point(px(anchor.x), px(anchor.y)),
                    size,
                ))),
                titlebar: None,
                // A nonactivating AppKit panel accepts clicks while another
                // app remains active; a Floating window can lose the click
                // while macOS tries to activate this menu-bar-only app.
                kind: WindowKind::PopUp,
                is_resizable: false,
                is_minimizable: false,
                is_movable: false,
                ..Default::default()
            },
            move |window, cx| {
                cx.new(|cx| Panel::new(prepared, events, update_text, status, &detail, window, cx))
            },
        )?;
        opened.update(cx, |panel, _, cx| panel.set_devices(devices.clone(), cx))?;
        opened.update(cx, |_, window, _| window.activate_window())?;
        Ok(opened)
    }

    fn animates(&self) -> bool {
        true
    }
}

impl Drop for StatusItem {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        NSStatusBar::systemStatusBar().removeStatusItem(&self.item);
    }
}

pub(crate) fn install(
    cx: &mut App,
    smoke: Option<std::rc::Rc<std::cell::Cell<bool>>>,
    config: Option<std::path::PathBuf>,
    runtime: Runtime,
) -> anyhow::Result<()> {
    let mtm = MainThreadMarker::new().ok_or_else(|| anyhow::anyhow!("main thread required"))?;
    let app = NSApplication::sharedApplication(mtm);
    let reduced_motion = NSWorkspace::sharedWorkspace().accessibilityDisplayShouldReduceMotion();
    if !app.setActivationPolicy(NSApplicationActivationPolicy::Accessory) {
        anyhow::bail!("accessory activation policy rejected");
    }
    let (sender, receiver) = async_channel::bounded(32);
    let testing = smoke.is_some();
    let action = TrayAction::new(mtm, sender.clone());
    let stop = runtime.stop.clone();
    if let Some(config) = config {
        crate::worker::start(config, sender.clone(), stop.clone());
    }
    let discovery_request = if testing {
        None
    } else {
        Some(crate::devices::start(sender.clone(), stop.clone()))
    };
    let update_request = Some(if smoke.is_none() {
        crate::update_ui::start(sender.clone(), stop.clone())
    } else {
        crate::update_ui::start_smoke(sender.clone(), stop.clone())
    });
    let item = NSStatusBar::systemStatusBar().statusItemWithLength(28.0);
    let button = item
        .button(mtm)
        .ok_or_else(|| anyhow::anyhow!("status button unavailable"))?;
    let image = NSImage::initWithData(
        NSImage::alloc(),
        &NSData::with_bytes(include_bytes!("../../assets/status-template.pdf")),
    )
    .ok_or_else(|| anyhow::anyhow!("invalid embedded icon"))?;
    image.setSize(NSSize::new(18.0, 18.0));
    image.setTemplate(true);
    button.setImage(Some(&image));
    button.setToolTip(Some(ns_string!("Mi Clip · 尚未连接")));
    // SAFETY: The target is retained for the entire event loop. Selector signature
    // matches the action method above; Cocoa supplies the status button as sender.
    unsafe {
        button.setTarget(Some(&action));
        button.setAction(Some(sel!(togglePanel:)));
    }
    mi_clip::updater::mark_ready()?;
    if let Some(passed) = smoke {
        smoke_test(cx, &button, &sender, passed);
    }
    if std::env::var_os("MICLIP_DIAGNOSTICS").is_some() {
        println!("Mi Clip status item ready; no startup window.");
    }
    let status = StatusItem {
        item,
        _action: action,
        stop,
        button,
        idle: image,
        icons: FileIcons::new(),
        clock: Instant::now(),
        reduced_motion,
    };
    run(
        cx,
        sender,
        receiver,
        status,
        runtime,
        testing,
        reduced_motion,
        discovery_request,
        update_request,
    );
    Ok(())
}

fn smoke_test(
    cx: &mut App,
    button: &NSStatusBarButton,
    events: &Sender<TrayEvent>,
    passed: std::rc::Rc<std::cell::Cell<bool>>,
) {
    let test_button = button.clone();
    let test_events = events.clone();
    let quit_expected = std::rc::Rc::new(std::cell::Cell::new(false));
    let quitting = quit_expected.clone();
    cx.on_app_quit(move |_| {
        if !quitting.get() {
            eprintln!("UI smoke test ended before the Quit button was clicked");
            std::process::exit(1);
        }
        if quitting.get() {
            passed.set(true);
            println!("PASS: native file feedback frames, completion badge acknowledgement, update click feedback, toggle, Escape, outside-close event and Quit");
        }
        std::future::ready(())
    }).detach();
    cx.spawn(async move |cx| {
        use std::time::Duration;
        let result = async {
            cx.background_executor()
                .timer(Duration::from_millis(250))
                .await;
            // Synthetic lifecycle, no account, network, file write or OS banner.
            cx.update(|_| -> anyhow::Result<()> {
                let mut frames = FileIcons::new();
                for icon in [Icon::Connecting, Icon::Receiving, Icon::Saved, Icon::Failed] {
                    for frame in 0..12 {
                        anyhow::ensure!(
                            frames.image(icon, frame)?.isValid(),
                            "Invalid native vector frame"
                        );
                    }
                }
                Ok(())
            })?;
            for event in [
                FileEvent::Requested,
                FileEvent::Failed(mi_clip::file_feedback::Failure::Unavailable),
                FileEvent::Requested,
                FileEvent::Progress {
                    received: 4,
                    total: 10,
                },
                FileEvent::Progress {
                    received: 10,
                    total: 10,
                },
                FileEvent::Saved { files: 1 },
            ] {
                test_events.send(TrayEvent::File(event)).await?;
                cx.background_executor()
                    .timer(Duration::from_millis(250))
                    .await;
                cx.update(|_| -> anyhow::Result<()> {
                    anyhow::ensure!(
                        !test_button.image().is_none_or(|image| image.isTemplate()),
                        "File event did not change native icon"
                    );
                    if matches!(event, FileEvent::Saved { .. }) {
                        anyhow::ensure!(
                            test_button
                                .toolTip()
                                .is_some_and(|text| text.to_string().contains("保存")),
                            "Completion tooltip missing"
                        );
                    }
                    Ok(())
                })?;
                if matches!(event, FileEvent::Failed(_)) {
                    test_events
                        .send(TrayEvent::Status(
                            "已连接",
                            "此内容暂不支持 · 当前仅同步短文本".into(),
                        ))
                        .await?;
                    cx.background_executor()
                        .timer(Duration::from_millis(250))
                        .await;
                    cx.update(|_| -> anyhow::Result<()> {
                        anyhow::ensure!(
                            test_button
                                .toolTip()
                                .is_some_and(|text| text.to_string().contains("仅同步短文本")),
                            "Old file feedback hid clipboard format hint"
                        );
                        Ok(())
                    })?;
                }
            }
            // Populate enough synthetic peers to exercise the scroll area.
            test_events
                .send(TrayEvent::Devices(Ok((0..8)
                    .map(|i| crate::devices::Device {
                        name: format!("测试设备 {i}"),
                        host: format!("fixture-{i}.local."),
                        port: 1234,
                        device_type: if i == 0 { 1 } else { 2 },
                        addresses: vec![format!("192.0.2.{}:1234", i + 1).parse().unwrap()],
                    })
                    .collect())))
                .await?;
            cx.update(|cx| -> anyhow::Result<()> {
                anyhow::ensure!(cx.windows().is_empty(), "Unexpected startup window");
                // SAFETY: Retained target and button, main thread.
                unsafe {
                    test_button.performClick(None);
                }
                Ok(())
            })?;
            for step in 0..4 {
                cx.background_executor()
                    .timer(Duration::from_millis(700))
                    .await;
                cx.update(|cx| -> anyhow::Result<()> {
                    anyhow::ensure!(
                        test_button.image().is_some_and(|image| image.isTemplate()),
                        "Opening the panel did not acknowledge the badge"
                    );
                    anyhow::ensure!(
                        test_button.alphaValue() == 1.,
                        "Animation did not restore opacity"
                    );
                    let handle = cx
                        .windows()
                        .first()
                        .copied()
                        .and_then(|w| w.downcast::<Panel>())
                        .ok_or_else(|| anyhow::anyhow!("Popup missing before refresh"))?;
                    handle.update(cx, |panel, window, cx| {
                        panel.refresh(
                            "已连接",
                            if step == 0 { "" } else { "测试状态更新" },
                            window,
                            cx,
                        )?;
                        if step == 0 {
                            panel.update_label(&ui::current_version_label(), cx);
                        }
                        Ok::<(), anyhow::Error>(())
                    })??;
                    Ok(())
                })?;
                // Let the new Rhai tree commit its focus path and hitboxes.
                cx.background_executor()
                    .timer(Duration::from_millis(250))
                    .await;
                cx.update(|cx| -> anyhow::Result<()> {
                    use gpui_rhai::gpui::Keystroke;
                    anyhow::ensure!(cx.windows().len() == 1, "Click must open one popup");
                    let handle = cx.windows()[0]
                        .downcast::<Panel>()
                        .ok_or_else(|| anyhow::anyhow!("Wrong root"))?;
                    handle.update(cx, |panel, window, cx| -> anyhow::Result<()> {
                        panel.validate(cx)?;
                        anyhow::ensure!(
                            panel.device_count() == 8,
                            "Device discovery did not reach the popup"
                        );
                        anyhow::ensure!(
                            window.viewport_size().height >= px(320.0),
                            "Device list was clipped by the popup"
                        );
                        let _ = window;
                        Ok(())
                    })??;
                    cx.update_window(handle.into(), |_, window, cx| -> anyhow::Result<()> {
                        // Commit the refreshed layout before injecting native events,
                        // including when macOS throttles background drawing.
                        window.draw(cx).clear(cx);
                        if step == 1 {
                            window.dispatch_keystroke(Keystroke::parse("escape")?, cx);
                        } else if step == 0 || step == 3 {
                            // Route through AppKit as a real panel click would.
                            let mtm = MainThreadMarker::new().unwrap();
                            let app = NSApplication::sharedApplication(mtm);
                            let native = app.windows().iter()
                                .find(|w| w.isVisible() && (w.frame().size.width - 280.0).abs() < 1.0)
                                .ok_or_else(|| anyhow::anyhow!("Native popup missing"))?;
                            let (x, y) = if step == 0 { (60.0, 68.0) } else { (244.0, 92.0) };
                            for kind in [objc2_app_kit::NSEventType::LeftMouseDown, objc2_app_kit::NSEventType::LeftMouseUp] {
                                let event = objc2_app_kit::NSEvent::mouseEventWithType_location_modifierFlags_timestamp_windowNumber_context_eventNumber_clickCount_pressure(
                                    kind, objc2_foundation::NSPoint::new(x, f64::from(window.viewport_size().height) - y),
                                    objc2_app_kit::NSEventModifierFlags::empty(), (step + 1) as f64,
                                    native.windowNumber(), None, (step + 1) as isize, 1, 1.0,
                                ).ok_or_else(|| anyhow::anyhow!("Mouse event allocation failed"))?;
                                app.postEvent_atStart(&event, false);
                            }
                        }
                        Ok(())
                    })??;

                    Ok(())
                })?;
                if step == 0 {
                    cx.background_executor()
                        .timer(Duration::from_millis(250))
                        .await;
                    cx.update(|cx| -> anyhow::Result<()> {
                        let handle = cx.windows()[0]
                            .downcast::<Panel>()
                            .ok_or_else(|| anyhow::anyhow!("Update popup disappeared"))?;
                        handle.update(cx, |panel, _, _| -> anyhow::Result<()> {
                            anyhow::ensure!(
                                panel.update_label == "检查中…",
                                "Fast result hid the checking state before it could be seen"
                            );
                            Ok(())
                        })??;
                        Ok(())
                    })?;
                    cx.background_executor()
                        .timer(Duration::from_millis(1500))
                        .await;
                    cx.update(|cx| -> anyhow::Result<()> {
                        let handle = cx.windows()[0]
                            .downcast::<Panel>()
                            .ok_or_else(|| anyhow::anyhow!("Update popup disappeared"))?;
                        handle.update(cx, |panel, _, _| -> anyhow::Result<()> {
                            anyhow::ensure!(
                                panel.update_label == ui::current_version_label(),
                                "Fast update check did not finish"
                            );
                            Ok(())
                        })??;
                        unsafe {
                            test_button.performClick(None);
                        }
                        Ok(())
                    })?;
                }
                if step == 2 {
                    // Exercise the event sent by the native mouse monitor.
                    // macOS may deny activation to an automated background
                    // launch, so do not infer an outside click from keyWindow.
                    test_events.try_send(TrayEvent::Close)?;
                }
                if step == 3 {
                    // The click must itself request application quit. A timed
                    // cleanup is a failure and cannot mark this test passed.
                    cx.background_executor()
                        .timer(Duration::from_millis(400))
                        .await;
                    anyhow::bail!("Visible Quit button did not quit the application");
                }
                cx.background_executor()
                    .timer(Duration::from_millis(300))
                    .await;
                cx.update(|cx| -> anyhow::Result<()> {
                    anyhow::ensure!(
                        cx.windows().is_empty(),
                        "Close path {step} left a popup open"
                    );
                    if step == 2 {
                        quit_expected.set(true);
                    }
                    unsafe {
                        test_button.performClick(None);
                    }
                    Ok(())
                })?;
            }
            Ok::<(), anyhow::Error>(())
        }
        .await;
        quit_expected.set(false);
        if let Err(error) = result {
            eprintln!("UI smoke test failed: {error}");
            std::process::exit(1);
        }
        let _ = cx.update(|cx| {
            cx.quit();
            Ok::<(), anyhow::Error>(())
        });
    })
    .detach();
}
