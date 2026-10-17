use gpui_rhai::gpui::{
    Context, InteractiveElement, IntoElement, ParentElement, Render, StatefulInteractiveElement,
    Styled, Subscription, Window, div, px, rgba,
};
use gpui_rhai::{
    EmbeddedScriptSource, EmbeddedScriptView, ModuleId, PreparedScriptView, ScriptViewConfig,
    ScriptViewHandle, ScriptViewHost,
};
use std::collections::BTreeMap;

pub fn prepare() -> anyhow::Result<PreparedScriptView> {
    prepare_status("尚未连接", "请先完成设备登录")
}
pub fn prepare_status(status: &str, detail: &str) -> anyhow::Result<PreparedScriptView> {
    let id = ModuleId::parse("panel")?;
    Ok(EmbeddedScriptView::new(
        id.clone(),
        EmbeddedScriptSource::new(BTreeMap::from([(
            id,
            include_str!("../ui/panel.rhai")
                .replace("\"尚未连接\"", &serde_json::to_string(status)?)
                .replace("\"等待设备认证\"", &serde_json::to_string(detail)?),
        )])),
        include_str!("../ui/theme.rhai"),
    )
    .prepare()
    .map_err(|error| anyhow::anyhow!(error.to_string()))?)
}

pub struct Panel {
    host: ScriptViewHost,
    view: Result<ScriptViewHandle, String>,
    _blur: Subscription,
    _outside_click: OutsideClickMonitor,
    events: async_channel::Sender<crate::tray::TrayEvent>,
    update_label: String,
}
impl Panel {
    pub fn update_label(&mut self, label: &str, cx: &mut Context<Self>) {
        self.update_label = label.to_owned();
        cx.notify();
    }
    pub fn refresh(
        &mut self,
        status: &str,
        detail: &str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> anyhow::Result<()> {
        let prepared = prepare_status(status, detail)?;
        if let Ok(view) = &self.view {
            let _ = view.dispose(cx);
        }
        self.view = prepared
            .mount(
                ScriptViewConfig::new("status"),
                self.host.clone(),
                window,
                cx,
            )
            .map_err(|error| error.to_string());
        if let Ok(view) = &self.view {
            let _ = view.focus(window, cx);
        }
        cx.notify();
        Ok(())
    }
    pub fn validate(&self, cx: &gpui_rhai::gpui::App) -> anyhow::Result<()> {
        anyhow::ensure!(
            self._outside_click.0.is_some(),
            "Outside click monitor unavailable"
        );
        let view = self
            .view
            .as_ref()
            .map_err(|error| anyhow::anyhow!(error.clone()))?;
        anyhow::ensure!(
            view.root(cx)
                .map_err(|e| anyhow::anyhow!(e.to_string()))?
                .is_some(),
            "No committed Rhai tree"
        );
        if let Some(error) = view
            .last_error(cx)
            .map_err(|e| anyhow::anyhow!(e.to_string()))?
        {
            anyhow::bail!(error);
        }
        Ok(())
    }
    pub fn new(
        prepared: PreparedScriptView,
        events: async_channel::Sender<crate::tray::TrayEvent>,
        update_label: String,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let host = ScriptViewHost::new("status-panel", cx).expect("static host identifier");
        let view = prepared
            .mount(ScriptViewConfig::new("status"), host.clone(), window, cx)
            .map_err(|error| error.to_string());
        if let Ok(view) = &view {
            let _ = view.focus(window, cx);
        }
        let outside_click = OutsideClickMonitor::new(events.clone());
        let blur = cx.observe_window_activation(window, |_, window, _| {
            if !window.is_window_active() {
                window.remove_window();
            }
        });
        Self {
            host,
            view,
            _blur: blur,
            _outside_click: outside_click,
            events,
            update_label,
        }
    }
}
// AppKit popup panels can remain nonactivating, so a key-window change alone
// does not reliably detect clicks in other apps. Monitor mouse-down only while
// this popup exists; no polling, keyboard capture or accessibility permission.
struct OutsideClickMonitor(Option<objc2::rc::Retained<objc2::runtime::AnyObject>>);
impl OutsideClickMonitor {
    fn new(events: async_channel::Sender<crate::tray::TrayEvent>) -> Self {
        use objc2_app_kit::{NSEvent, NSEventMask};
        let handler = block2::RcBlock::new(move |_: std::ptr::NonNull<NSEvent>| {
            let _ = events.try_send(crate::tray::TrayEvent::Close);
        });
        Self(NSEvent::addGlobalMonitorForEventsMatchingMask_handler(
            NSEventMask::LeftMouseDown | NSEventMask::RightMouseDown | NSEventMask::OtherMouseDown,
            &handler,
        ))
    }
}
impl Drop for OutsideClickMonitor {
    fn drop(&mut self) {
        if let Some(monitor) = self.0.take() {
            // SAFETY: This token came from NSEvent's monitor API above and is
            // removed exactly once on the application's main thread.
            unsafe {
                objc2_app_kit::NSEvent::removeMonitor(&monitor);
            }
        }
    }
}
impl Render for Panel {
    fn render(&mut self, _: &mut Window, _: &mut Context<Self>) -> impl IntoElement {
        let events = self.events.clone();
        let checking = self.update_label == "检查中…";
        let content = match &self.view {
            Ok(view) => view
                .element()
                .expect("mounted status panel")
                .into_any_element(),
            Err(error) => div()
                .p(px(16.0))
                .child(format!("界面加载失败：{error}"))
                .into_any_element(),
        };
        self.host.container(
            div()
                .size_full()
                .flex()
                .flex_col()
                .bg(rgba(0x191b20ff))
                .text_color(rgba(0xf0f2f5ff))
                .on_action(|_: &crate::ClosePanel, window, _| window.remove_window())
                .on_key_down(|event, window, _| {
                    if event.keystroke.key == "escape" {
                        window.remove_window();
                    }
                })
                // ScriptViewHandle's host has size_full(), so constrain it to
                // the content area instead of letting it push buttons offscreen.
                .child(
                    div()
                        .h(px(132.0))
                        .flex_shrink_0()
                        .overflow_hidden()
                        .child(content),
                )
                .child(
                    div()
                        .h(px(48.0))
                        .flex_shrink_0()
                        .flex()
                        .items_center()
                        .justify_between()
                        .px(px(12.0))
                        .child(
                            div()
                                .id("update")
                                .px(px(8.0))
                                .py(px(6.0))
                                .text_size(px(12.0))
                                .rounded(px(6.0))
                                .cursor_pointer()
                                .hover(|style| style.bg(rgba(0x2b3038ff)))
                                .on_click(move |_, _, _| {
                                    if !checking {
                                        let _ =
                                            events.try_send(crate::tray::TrayEvent::CheckUpdate);
                                    }
                                })
                                .child(self.update_label.clone()),
                        )
                        .child(
                            div()
                                .flex()
                                .gap(px(4.0))
                                .child(
                                    div()
                                        .id("close")
                                        .px(px(8.0))
                                        .py(px(6.0))
                                        .text_size(px(12.0))
                                        .rounded(px(6.0))
                                        .cursor_pointer()
                                        .hover(|style| style.bg(rgba(0x2b3038ff)))
                                        .on_click(|_, window, _| window.remove_window())
                                        .child("关闭"),
                                )
                                .child(
                                    div()
                                        .id("quit")
                                        .px(px(8.0))
                                        .py(px(6.0))
                                        .text_size(px(12.0))
                                        .rounded(px(6.0))
                                        .cursor_pointer()
                                        .hover(|style| style.bg(rgba(0x2b3038ff)))
                                        .on_click(|_, _, cx| cx.quit())
                                        .child("退出"),
                                ),
                        ),
                ),
        )
    }
}
