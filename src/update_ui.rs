use crate::tray::TrayEvent;
use async_channel::Sender;
use mi_clip::updater::{self, Check, PendingUpdate};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::Duration,
};

pub enum Notice {
    Checking,
    Current,
    Unpublished,
    Failed,
    Ready(PendingUpdate),
}

pub fn start(events: Sender<TrayEvent>, stop: Arc<AtomicBool>) -> mpsc::SyncSender<()> {
    let (request, receive) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut delay = Duration::from_secs(10);
        loop {
            match receive.recv_timeout(delay) {
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
                _ => {}
            }
            if stop.load(Ordering::Relaxed) {
                break;
            }
            let _ = events.try_send(TrayEvent::Update(Notice::Checking));
            let notice = match updater::check() {
                Ok(Check::Current) => Notice::Current,
                Ok(Check::Unpublished) => Notice::Unpublished,
                Ok(Check::Ready(pending)) => Notice::Ready(pending),
                Err(_) => Notice::Failed,
            };
            let ready = matches!(&notice, Notice::Ready(_));
            if ready {
                // Keep one verified download until installation; don't fetch it hourly.
                let _ = events.send_blocking(TrayEvent::Update(notice));
                break;
            }
            let _ = events.try_send(TrayEvent::Update(notice));
            delay = Duration::from_secs(3600);
        }
    });
    request
}
