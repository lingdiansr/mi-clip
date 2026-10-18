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
        while !stop.load(Ordering::Relaxed) {
            let _ = events.try_send(TrayEvent::Status("连接中", "请保持手机互联功能开启".into()));
            let connected = std::cell::Cell::new(false);
            let _ = handshake::sync_once(&config, &stop, &|event| {
                let status = match event {
                    SyncEvent::File(event) => {
                        let _ = events.send_blocking(TrayEvent::File(event));
                        return;
                    }
                    SyncEvent::Connected => {
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
                    SyncEvent::FileClipboardRequested => {
                        ("已连接", "手机正在取用复制的文件".into())
                    }
                    SyncEvent::FileClipboardSent(files) => {
                        ("已连接", format!("已向手机发送 {files} 个文件"))
                    }
                    SyncEvent::FileClipboardFailed => {
                        ("已连接", "文件取用失败 · 请重新复制后粘贴".into())
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
            let _ = events.try_send(TrayEvent::Status(
                "等待重连",
                "手机离线或认证失效 · 自动重试".into(),
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
