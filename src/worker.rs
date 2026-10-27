use crate::tray::TrayEvent;
use async_channel::Sender;
use mi_clip::handshake::{self, SyncEvent};
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

pub fn start(config: PathBuf, events: Sender<TrayEvent>, stop: Arc<AtomicBool>) {
    std::thread::spawn(move || {
        let mut backoff = 2;
        let mut last_error = String::new();
        let analytics = std::cell::RefCell::new(mi_clip::analytics::Session::default());
        while !stop.load(Ordering::Relaxed) {
            analytics.borrow_mut().begin();
            let _ = events.try_send(TrayEvent::Status("连接中", last_error.clone()));
            let connected = std::cell::Cell::new(false);
            let attempted = std::cell::Cell::new(None);
            let phase = std::cell::Cell::new("发现设备／读取配置");
            let result = handshake::sync_once(&config, &stop, &|event| {
                if let Some(event) = analytics.borrow_mut().observe(&event) {
                    mi_clip::analytics::capture(event);
                }
                let status = match event {
                    SyncEvent::File(event) => {
                        let _ = events.send_blocking(TrayEvent::File(event));
                        return;
                    }
                    SyncEvent::Connecting(endpoint) => {
                        attempted.set(Some(endpoint));
                        phase.set("建立设备通道");
                        let _ = events.send_blocking(TrayEvent::Connecting(endpoint));
                        ("连接中", last_error.clone())
                    }
                    SyncEvent::Authenticating => {
                        phase.set("设备认证");
                        ("认证中", last_error.clone())
                    }
                    SyncEvent::Connected => {
                        mi_clip::share_queue::set_connected(attempted.get());
                        phase.set("已连接／同步");
                        connected.set(true);
                        ("已连接", String::new())
                    }
                    SyncEvent::Received(_) | SyncEvent::Sent(_) => ("已连接", String::new()),
                    SyncEvent::Unsupported => ("已连接", "已跳过超出长度限制的内容".into()),
                    SyncEvent::FileClipboardSkipped => {
                        ("已连接", "该文件暂不支持同步，请复制普通文件后重试".into())
                    }
                    SyncEvent::FileClipboardOffered(files) => (
                        "已连接",
                        format!("{files} 个文件已就绪 · 可在手机兼容应用粘贴"),
                    ),
                    SyncEvent::ImageClipboardOffered => {
                        ("已连接", "图片已就绪 · 可在手机兼容应用粘贴".into())
                    }
                    SyncEvent::FileClipboardRequested => {
                        ("已连接", "手机正在取用复制的文件".into())
                    }
                    SyncEvent::FileClipboardSent(files) => {
                        ("已连接", format!("已向手机发送 {files} 个文件"))
                    }
                    SyncEvent::FileClipboardFailed => {
                        ("已连接", "文件取用失败 · 请重新复制后粘贴".into())
                    }
                    SyncEvent::ShareStarted => ("已连接", "正在连接所选分享设备".into()),
                    SyncEvent::ShareCompleted(files) => {
                        ("已连接", format!("手机已确认接收 {files} 个文件"))
                    }
                    SyncEvent::ShareFailed => {
                        ("已连接", "文件分享失败 · 请查看共享窗口后重试".into())
                    }
                    SyncEvent::UnsupportedClipboard => {
                        ("已连接", "手机复制的此类内容暂不支持".into())
                    }
                };
                let _ = events.try_send(TrayEvent::Status(status.0, status.1));
            });
            if connected.get() {
                mi_clip::share_queue::set_connected(None);
            }
            if stop.load(Ordering::Relaxed) {
                break;
            }
            // A selected device ends the old session deliberately. Connect to
            // that selection immediately, without inheriting its retry delay.
            if switch_target(attempted.get(), mi_clip::share_queue::pending_target()) {
                backoff = 2;
                last_error.clear();
                continue;
            }
            if result.is_err() {
                for event in analytics.borrow_mut().failed() {
                    mi_clip::analytics::capture(event);
                }
            }
            let _ = events.try_send(TrayEvent::File(mi_clip::file_feedback::Event::Failed(
                mi_clip::file_feedback::Failure::Disconnected,
            )));
            if connected.get() {
                backoff = 2;
            }
            last_error = match result {
                Err(error) => {
                    let detail = format!("{}失败：{error:#}", phase.get());
                    if let Some(target) = attempted.get() {
                        mi_clip::share_queue::fail_pending(target, &detail);
                    }
                    let timestamp = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    eprintln!("[{timestamp}] Mi Clip: {detail}; retry in {backoff}s");
                    detail
                }
                Ok(()) => "连接已结束".into(),
            };
            let _ = events.try_send(TrayEvent::Status(
                "等待重连",
                format!("{last_error} · {backoff} 秒后重试"),
            ));
            let pending = mi_clip::share_queue::pending_target();
            let mut selected = false;
            for _ in 0..backoff * 4 {
                if stop.load(Ordering::Relaxed) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(250));
                let next = mi_clip::share_queue::pending_target();
                if next.is_some() && next != pending {
                    selected = true;
                    break;
                }
            }
            backoff = if selected { 2 } else { (backoff * 2).min(30) };
        }
    });
}

fn switch_target(
    attempted: Option<std::net::SocketAddr>,
    selected: Option<std::net::SocketAddr>,
) -> bool {
    matches!((attempted, selected), (Some(a), Some(b)) if a != b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_selection_switches_immediately_but_failure_does_not_spin() {
        let first = "127.0.0.1:1".parse().unwrap();
        let second = "127.0.0.1:2".parse().unwrap();
        assert!(switch_target(Some(first), Some(second)));
        assert!(!switch_target(Some(first), Some(first)));
        assert!(!switch_target(None, Some(second)));
        assert!(!switch_target(Some(first), None));
    }

    #[test]
    fn missing_config_reports_the_error_and_keeps_it_during_retry() {
        let (events, receiver) = async_channel::unbounded();
        let stop = Arc::new(AtomicBool::new(false));
        let missing = std::env::temp_dir()
            .join(format!("mi-clip-missing-{}", std::process::id()))
            .join("config.json");
        assert!(!missing.exists());
        start(missing, events, stop.clone());
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut failure = None;
        let mut retained = false;
        while std::time::Instant::now() < deadline {
            if let Ok(TrayEvent::Status(status, detail)) = receiver.try_recv() {
                if status == "等待重连" {
                    assert!(detail.contains("发现设备／读取配置失败"));
                    assert!(detail.contains("os error 2"));
                    assert!(detail.contains("2 秒后重试"));
                    failure = Some(detail);
                } else if status == "连接中" && failure.is_some() {
                    retained = detail.contains("os error 2");
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        stop.store(true, Ordering::Relaxed);
        assert!(failure.is_some(), "connection error was not reported");
        assert!(retained, "retry cleared the previous connection error");
    }
}
