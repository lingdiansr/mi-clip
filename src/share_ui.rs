//! Native Linux share picker: choose one phone, then follow the transfer.
//!
//! Discovery only proves a phone is reachable; authentication happens in the
//! worker. The window therefore never claims success before the phone confirms.
use crate::devices::Devices;
use gpui_rhai::gpui::{
    AppContext, Context, InteractiveElement, IntoElement, ParentElement, Render,
    StatefulInteractiveElement, Styled, Window, div, px, rgba,
};
use mi_clip::share_queue::{LocalShare, ShareState};
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

/// A catalogue older than this is not trustworthy for choosing a target.
const STALE_AFTER: Duration = Duration::from_secs(45);
/// Refresh the phone list while the user is choosing.
const REFRESH_EVERY: Duration = Duration::from_secs(8);
/// Sender polls progress every 250 ms.
const TICK: Duration = Duration::from_millis(250);

pub(crate) struct ShareInit {
    pub files: Vec<PathBuf>,
    pub events: async_channel::Sender<crate::tray::TrayEvent>,
    pub reservation: Arc<AtomicBool>,
    /// False when no account configuration or worker exists.
    pub logged_in: bool,
}

pub(crate) struct ShareWindow {
    files: Vec<PathBuf>,
    total: u64,
    devices: Devices,
    task: Option<LocalShare>,
    preparing: bool,
    message: Option<String>,
    events: async_channel::Sender<crate::tray::TrayEvent>,
    reservation: Arc<AtomicBool>,
    logged_in: bool,
    last_refresh: Instant,
    last_progress: Option<(ShareState, u64)>,
    /// The isolated smoke harness may drive one deterministic action.
    fixture_done: bool,
}

impl ShareWindow {
    pub(crate) fn new(cx: &mut Context<Self>, init: ShareInit) -> Self {
        let total = init
            .files
            .iter()
            .filter_map(|path| std::fs::metadata(path).ok())
            .filter(|metadata| metadata.is_file())
            .map(|metadata| metadata.len())
            .sum();
        cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor().timer(TICK).await;
                let done = this
                    .update_in(cx, |window, handle, cx| window.tick(handle, cx))
                    .unwrap_or(true);
                if done {
                    break;
                }
            }
        })
        .detach();
        Self {
            total,
            files: init.files,
            devices: Devices::default(),
            task: None,
            preparing: false,
            message: None,
            events: init.events,
            reservation: init.reservation,
            logged_in: init.logged_in,
            last_refresh: Instant::now(),
            last_progress: None,
            fixture_done: false,
        }
    }

    pub(crate) fn set_devices(&mut self, devices: Devices, cx: &mut Context<Self>) {
        self.devices = devices;
        cx.notify();
    }

    /// First selectable phone, used by the deterministic smoke harness.
    fn first_target(&self) -> Option<std::net::SocketAddr> {
        let stale = self
            .devices
            .updated
            .is_none_or(|updated| updated.elapsed() > STALE_AFTER);
        if stale || !self.logged_in || self.task.is_some() || self.preparing {
            return None;
        }
        self.devices
            .entries
            .iter()
            .filter(|device| device.device_type == 1)
            .find_map(|device| device.addresses.iter().find(|a| a.is_ipv4()).copied())
    }

    /// Lets the smoke harness choose or cancel without a physical click.
    fn fixture(&mut self, window: &mut Window, cx: &mut Context<Self>) -> bool {
        if self.fixture_done {
            return false;
        }
        let Ok(mode) = std::env::var("MICLIP_SHARE_FIXTURE") else {
            return false;
        };
        match mode.as_str() {
            "cancel" => {
                self.fixture_done = true;
                if std::env::var_os("MICLIP_DIAGNOSTICS").is_some() {
                    println!("Mi Clip share: fixture cancels the picker");
                }
                window.remove_window();
                true
            }
            "select" => match self.first_target() {
                Some(target) => {
                    self.fixture_done = true;
                    if std::env::var_os("MICLIP_DIAGNOSTICS").is_some() {
                        println!("Mi Clip share: fixture selects {target}");
                    }
                    self.select(target, cx);
                    false
                }
                None => false,
            },
            _ => false,
        }
    }

    /// True when the window should close.
    fn tick(&mut self, window: &mut Window, cx: &mut Context<Self>) -> bool {
        if self.fixture(window, cx) {
            return true;
        }
        if let Some((state, sent, _, _)) = self.progress() {
            // The phone confirmed completion: nothing left to show.
            if state == ShareState::Completed {
                window.remove_window();
                return true;
            }
            if self.last_progress != Some((state, sent)) {
                self.last_progress = Some((state, sent));
                cx.notify();
            }
            return false;
        }
        // Keep the phone list fresh while the user is still choosing.
        if self.logged_in
            && self.last_refresh.elapsed() >= REFRESH_EVERY
            && self
                .events
                .try_send(crate::tray::TrayEvent::RefreshDevices)
                .is_ok()
        {
            self.last_refresh = Instant::now();
        }
        false
    }

    fn select(&mut self, target: std::net::SocketAddr, cx: &mut Context<Self>) {
        if self.task.is_some() || self.preparing || !self.logged_in {
            return;
        }
        self.preparing = true;
        self.message = None;
        cx.notify();
        let files = self.files.clone();
        cx.spawn(async move |this, cx| {
            let result = cx
                .background_spawn(async move { mi_clip::share_queue::enqueue(files, target) })
                .await;
            this.update(cx, |window, cx| {
                window.preparing = false;
                match result {
                    Ok(task) => window.task = Some(task),
                    Err(error) => {
                        if std::env::var_os("MICLIP_DIAGNOSTICS").is_some() {
                            println!("Mi Clip share: task unavailable: {error:#}");
                        }
                        window.message = Some(format!("{error:#}"));
                    }
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn progress(&self) -> Option<(ShareState, u64, u64, Option<String>)> {
        let task = self.task.as_ref()?;
        let snapshot = task.snapshot();
        Some((
            snapshot.state,
            snapshot.sent,
            snapshot.total,
            snapshot.message,
        ))
    }

    fn status_line(&self) -> String {
        if !self.logged_in {
            return "请先完成设备登录".into();
        }
        if let Some((state, sent, total, message)) = self.progress() {
            return match state {
                ShareState::Connecting => "正在连接所选设备".into(),
                ShareState::Waiting => "等待手机接收".into(),
                ShareState::Sending => format!("已发送 {sent} / {total} 字节"),
                ShareState::Completed => "已完成".into(),
                ShareState::Failed => {
                    format!("失败：{}", message.unwrap_or_else(|| "未知错误".into()))
                }
                ShareState::Cancelled => "已取消".into(),
            };
        }
        if self.preparing {
            return "正在打开并校验所选文件…".into();
        }
        if let Some(message) = &self.message {
            return message.clone();
        }
        if self.devices.failed {
            return "未发现设备或多播不可用 · 请检查局域网与防火墙".into();
        }
        if self.devices.scanning {
            return "正在发现局域网设备…".into();
        }
        "选择一台手机，仅向它发送".into()
    }

    fn rows(&self) -> Vec<(usize, String, String, Option<std::net::SocketAddr>)> {
        let stale = self
            .devices
            .updated
            .is_none_or(|updated| updated.elapsed() > STALE_AFTER);
        let selectable = self.logged_in
            && !stale
            && !self.devices.scanning
            && self.task.is_none()
            && !self.preparing;
        self.devices
            .entries
            .iter()
            .enumerate()
            .map(|(index, device)| {
                let address = device.addresses.iter().find(|a| a.is_ipv4()).copied();
                let detail = if device.device_type != 1 {
                    "已发现 · 暂不支持分享".to_owned()
                } else if stale {
                    "列表已过期 · 请刷新".to_owned()
                } else if let Some(address) = address {
                    format!("可连接 · {address}")
                } else {
                    "缺少 IPv4 地址".to_owned()
                };
                (
                    index,
                    format!("{} · {}", device.name, device.kind()),
                    detail,
                    address.filter(|_| selectable && device.device_type == 1),
                )
            })
            .collect()
    }

    fn cancel_or_close(&mut self, window: &mut Window) {
        if let Some(task) = &self.task {
            task.cancel();
        }
        window.remove_window();
    }
}

impl Drop for ShareWindow {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.cancel();
        }
        self.reservation.store(false, Ordering::SeqCst);
    }
}

impl Render for ShareWindow {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let rows = self.rows();
        let mut list = div()
            .id("share-devices")
            .flex_1()
            .min_h(px(0.0))
            .overflow_y_scroll();
        for (index, name, detail, target) in rows {
            let mut row = div()
                .id(("share-device", index))
                .flex()
                .flex_col()
                .gap(px(3.0))
                .py(px(7.0))
                .px(px(6.0))
                .rounded(px(6.0))
                .child(div().text_ellipsis().child(name))
                .child(
                    div()
                        .text_size(px(10.0))
                        .text_color(rgba(0xa4acbaff))
                        .text_ellipsis()
                        .child(detail),
                );
            if let Some(target) = target {
                row = row
                    .cursor_pointer()
                    .hover(|style| style.bg(rgba(0x2b3038ff)))
                    .on_click(cx.listener(move |window, _, _, cx| window.select(target, cx)));
            }
            list = list.child(row);
        }
        if self.devices.entries.is_empty() {
            list = list.child(div().py(px(12.0)).text_color(rgba(0xa4acbaff)).child(
                if self.devices.scanning {
                    "正在发现局域网设备…"
                } else {
                    "未发现手机 · 请解锁并开启互联"
                },
            ));
        }
        let finished = matches!(
            self.progress().map(|progress| progress.0),
            Some(ShareState::Completed | ShareState::Failed | ShareState::Cancelled)
        );
        let cancel_label = if finished { "关闭" } else { "取消" };
        div()
            .size_full()
            .flex()
            .flex_col()
            .bg(rgba(0x191b20ff))
            .text_color(rgba(0xf0f2f5ff))
            .text_size(px(12.0))
            .on_action(|_: &crate::ClosePanel, window, _| window.remove_window())
            .on_key_down(|event, window, _| {
                if event.keystroke.key == "escape" {
                    window.remove_window();
                }
            })
            .child(
                div()
                    .flex_shrink_0()
                    .p(px(14.0))
                    .flex()
                    .flex_col()
                    .gap(px(6.0))
                    .child(div().text_size(px(13.0)).child(format!(
                        "分享 {} 个文件 · 合计 {} 字节",
                        self.files.len(),
                        self.total
                    )))
                    .child(div().text_color(rgba(0xa4acbaff)).child(self.status_line())),
            )
            .child(
                div()
                    .flex_shrink_0()
                    .px(px(14.0))
                    .pb(px(4.0))
                    .text_size(px(10.0))
                    .text_color(rgba(0xa4acbaff))
                    .child("发现位置不代表已通过账号认证；连接时会重新认证所选手机"),
            )
            .child(div().flex_1().min_h(px(0.0)).px(px(14.0)).child(list))
            .child(
                div()
                    .flex_shrink_0()
                    .h(px(44.0))
                    .flex()
                    .items_center()
                    .justify_end()
                    .gap(px(8.0))
                    .px(px(14.0))
                    .child(
                        div()
                            .id("share-refresh")
                            .px(px(8.0))
                            .py(px(6.0))
                            .rounded(px(6.0))
                            .cursor_pointer()
                            .hover(|style| style.bg(rgba(0x2b3038ff)))
                            .on_click(cx.listener(|window, _, _, cx| {
                                if window.task.is_none()
                                    && !window.devices.scanning
                                    && window
                                        .events
                                        .try_send(crate::tray::TrayEvent::RefreshDevices)
                                        .is_ok()
                                {
                                    window.devices.scanning = true;
                                    cx.notify();
                                }
                            }))
                            .child(if self.devices.scanning {
                                "发现中…"
                            } else {
                                "刷新"
                            }),
                    )
                    .child(
                        div()
                            .id("share-cancel")
                            .px(px(8.0))
                            .py(px(6.0))
                            .rounded(px(6.0))
                            .cursor_pointer()
                            .hover(|style| style.bg(rgba(0x2b3038ff)))
                            .on_click(cx.listener(|window, _, handle, _| {
                                window.cancel_or_close(handle);
                            }))
                            .child(cancel_label),
                    ),
            )
    }
}
