use crate::tray::TrayEvent;
use async_channel::Sender;
use mi_clip::updater::{self, Check, PendingUpdate};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

pub enum Notice {
    Checking,
    Downloading(String),
    Current,
    Unpublished,
    Failed,
    Ready(PendingUpdate),
}

pub fn start(events: Sender<TrayEvent>, stop: Arc<AtomicBool>) -> mpsc::SyncSender<()> {
    start_worker(events, stop, Duration::from_secs(10), |progress| {
        updater::check_with_progress(progress)
    })
}

// Exercise manual checks and fast responses in the GUI smoke test without network access.
pub fn start_smoke(events: Sender<TrayEvent>, stop: Arc<AtomicBool>) -> mpsc::SyncSender<()> {
    start_worker(events, stop, Duration::from_secs(3600), |_| {
        Ok(Check::Current)
    })
}

fn start_worker(
    events: Sender<TrayEvent>,
    stop: Arc<AtomicBool>,
    initial_delay: Duration,
    mut check: impl FnMut(&mut dyn FnMut(&str)) -> anyhow::Result<Check> + Send + 'static,
) -> mpsc::SyncSender<()> {
    let (request, receive) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut delay = initial_delay;
        loop {
            match receive.recv_timeout(delay) {
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
                _ => {}
            }
            if stop.load(Ordering::Relaxed) {
                break;
            }
            if events
                .send_blocking(TrayEvent::Update(Notice::Checking))
                .is_err()
            {
                break;
            }
            let started = Instant::now();
            let notice = match check(&mut |version| {
                let _ =
                    events.send_blocking(TrayEvent::Update(Notice::Downloading(version.into())));
            }) {
                Ok(Check::Current) => Notice::Current,
                Ok(Check::Unpublished) => Notice::Unpublished,
                Ok(Check::Ready(pending)) => Notice::Ready(pending),
                Err(_) => Notice::Failed,
            };
            // A fast response must not replace Checking before the next painted frame.
            std::thread::sleep(Duration::from_millis(1500).saturating_sub(started.elapsed()));
            if stop.load(Ordering::Relaxed) {
                break;
            }
            let ready = matches!(&notice, Notice::Ready(_));
            if ready {
                // Keep one verified download until installation; don't fetch it hourly.
                let _ = events.send_blocking(TrayEvent::Update(notice));
                break;
            }
            if events.send_blocking(TrayEvent::Update(notice)).is_err() {
                break;
            }
            delay = Duration::from_secs(3600);
        }
    });
    request
}
