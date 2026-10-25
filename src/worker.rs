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
        while !stop.load(Ordering::Relaxed) {
            let _ = events.try_send(TrayEvent::Status("连接中", last_error.clone()));
            let connected = std::cell::Cell::new(false);
            let phase = std::cell::Cell::new("发现设备／读取配置");
            let result = handshake::sync_once(&config, &stop, &|event| {
                let status = match event {
                    SyncEvent::File(event) => {
                        let _ = events.send_blocking(TrayEvent::File(event));
                        return;
                    }
                    SyncEvent::Connecting(endpoint) => {
                        phase.set("建立设备通道");
                        let _ = events.send_blocking(TrayEvent::Connecting(endpoint));
                        ("连接中", last_error.clone())
                    }
                    SyncEvent::Authenticating => {
                        phase.set("设备认证");
                        ("认证中", last_error.clone())
                    }
                    SyncEvent::Connected => {
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
                    SyncEvent::ShareStarted => {
                        ("已连接", "正在向手机发起文件分享 · 请在手机确认接收".into())
                    }
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
            if stop.load(Ordering::Relaxed) {
                break;
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
            for _ in 0..backoff * 4 {
                if stop.load(Ordering::Relaxed) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(250));
            }
            backoff = (backoff * 2).min(30);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

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
