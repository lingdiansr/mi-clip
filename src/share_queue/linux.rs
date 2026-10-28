//! In-memory outgoing share queue for the native Linux window.
//!
//! A window picks the target, so no directory handoff is involved: one control
//! block per task, claimed at most once, cancelled through the window handle.
use super::ShareDevice;
use crate::clipboard_files::Offer;
use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{
        Arc, LazyLock, Mutex, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

/// Progress of one share task as shown by the window.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ShareState {
    Connecting,
    Waiting,
    Sending,
    Completed,
    Failed,
    Cancelled,
}

pub struct ShareProgress {
    pub state: ShareState,
    pub sent: u64,
    pub total: u64,
    pub message: Option<String>,
}

struct Control {
    offer: Arc<Offer>,
    state: ShareState,
    sent: u64,
    total: u64,
    message: Option<String>,
    cancelled: bool,
    settled: bool,
    last_progress: Instant,
}

impl Control {
    fn snapshot(&self) -> ShareProgress {
        ShareProgress {
            state: self.state,
            sent: self.sent,
            total: self.total,
            message: self.message.clone(),
        }
    }

    fn fail(&mut self, message: &str) {
        // Terminal states never regress: a late transport error cannot undo a
        // cancellation, completion, or earlier failure.
        if self.settled {
            return;
        }
        self.state = ShareState::Failed;
        self.message = Some(message.to_owned());
        self.settled = true;
    }

    fn complete(&mut self) {
        if self.settled {
            return;
        }
        self.state = ShareState::Completed;
        self.sent = self.total;
        self.message = None;
        self.settled = true;
    }
}

struct Task {
    target: SocketAddr,
    control: Weak<Mutex<Control>>,
    claimed: bool,
}

/// The single task slot. Tests construct private instances so they never touch
/// the running application's queue.
pub(crate) struct Queue {
    slot: Mutex<Option<Task>>,
}

impl Queue {
    pub(crate) fn new() -> Self {
        Self {
            slot: Mutex::new(None),
        }
    }

    /// Queues one task; at most one may be outstanding at a time.
    pub(crate) fn enqueue(
        self: &Arc<Self>,
        paths: Vec<PathBuf>,
        target: SocketAddr,
    ) -> anyhow::Result<LocalShare> {
        super::validate_selected(target)?;
        let offer = Arc::new(Offer::open(paths, 0)?);
        let total = offer.files.iter().map(|file| file.size).sum();
        let control = Arc::new(Mutex::new(Control {
            offer,
            state: ShareState::Connecting,
            sent: 0,
            total,
            message: None,
            cancelled: false,
            settled: false,
            last_progress: Instant::now(),
        }));
        let mut slot = self.slot.lock().unwrap();
        if let Some(task) = slot.as_ref()
            && let Some(existing) = task.control.upgrade()
            && !existing.lock().unwrap().settled
        {
            anyhow::bail!("已有文件分享任务在进行中");
        }
        *slot = Some(Task {
            target,
            control: Arc::downgrade(&control),
            claimed: false,
        });
        Ok(LocalShare {
            queue: Arc::clone(self),
            control,
        })
    }

    /// Claims the task for `target`; a different target or a second claim gets
    /// nothing, so one request is never delivered twice.
    pub(crate) fn take_for(&self, target: SocketAddr) -> Option<Request> {
        let mut slot = self.slot.lock().unwrap();
        let task = slot.as_mut()?;
        if task.claimed || task.target != target {
            return None;
        }
        let control = task.control.upgrade()?;
        let offer = control.lock().unwrap().offer.clone();
        task.claimed = true;
        Some(Request {
            control,
            target,
            offer,
        })
    }

    pub(crate) fn pending_target(&self) -> Option<SocketAddr> {
        let slot = self.slot.lock().unwrap();
        let task = slot.as_ref()?;
        if task.claimed {
            return None;
        }
        let control = task.control.upgrade()?;
        let settled = control.lock().unwrap().settled;
        (!settled).then_some(task.target)
    }

    pub(crate) fn failure_scope(self: &Arc<Self>) -> Option<FailureScope> {
        let slot = self.slot.lock().unwrap();
        Some(FailureScope {
            queue: Arc::clone(self),
            control: slot.as_ref()?.control.clone(),
        })
    }

}

static QUEUE: LazyLock<Arc<Queue>> = LazyLock::new(|| Arc::new(Queue::new()));

pub(crate) fn queue() -> &'static Arc<Queue> {
    &QUEUE
}

/// Worker-side handle to the claimed task.
pub(crate) struct Request {
    control: Arc<Mutex<Control>>,
    pub target: SocketAddr,
    pub offer: Arc<Offer>,
}

impl Request {
    pub fn exists(&self) -> bool {
        let control = self.control.lock().unwrap();
        !control.cancelled && !control.settled
    }

    pub fn status(&mut self, state: &str, sent: u64) -> anyhow::Result<()> {
        let state = match state {
            "connecting" => ShareState::Connecting,
            "waiting" => ShareState::Waiting,
            "sending" => ShareState::Sending,
            other => anyhow::bail!("Unknown share state {other}"),
        };
        let mut control = self.control.lock().unwrap();
        if control.settled {
            return Ok(());
        }
        // Re-render repeated progress at most every 250 ms, but always show the
        // transition into sending.
        if state == ShareState::Sending
            && control.state == ShareState::Sending
            && control.last_progress.elapsed() < Duration::from_millis(250)
        {
            return Ok(());
        }
        control.last_progress = Instant::now();
        control.state = state;
        control.sent = sent;
        Ok(())
    }

    pub fn fail(&mut self, message: &str) -> anyhow::Result<()> {
        self.control.lock().unwrap().fail(message);
        Ok(())
    }

    pub fn complete(&mut self) -> anyhow::Result<()> {
        self.control.lock().unwrap().complete();
        Ok(())
    }
}

/// Window-side handle; dropping it before completion cancels the task.
pub struct LocalShare {
    queue: Arc<Queue>,
    control: Arc<Mutex<Control>>,
}

impl LocalShare {
    pub fn snapshot(&self) -> ShareProgress {
        self.control.lock().unwrap().snapshot()
    }

    pub fn cancel(&self) {
        let mut slot = self.queue.slot.lock().unwrap();
        let mut control = self.control.lock().unwrap();
        if !control.settled {
            control.state = ShareState::Cancelled;
            control.cancelled = true;
            control.settled = true;
        }
        drop(control);
        let same = slot
            .as_ref()
            .and_then(|task| task.control.upgrade())
            .is_some_and(|current| Arc::ptr_eq(&current, &self.control));
        if same {
            *slot = None;
        }
    }
}

impl Drop for LocalShare {
    fn drop(&mut self) {
        if !self.control.lock().unwrap().settled {
            self.cancel();
        }
    }
}

/// Identity of the outstanding task, captured before a session attempt.
pub struct FailureScope {
    queue: Arc<Queue>,
    control: Weak<Mutex<Control>>,
}

impl FailureScope {
    /// Settles only the task this scope was captured for; a newer task is never
    /// failed by an error from an older session.
    pub fn fail_if_pending(&self, message: &str) {
        let Some(control) = self.control.upgrade() else {
            return;
        };
        let current = {
            let slot = self.queue.slot.lock().unwrap();
            slot.as_ref().map(|task| task.control.clone())
        };
        if !current.is_some_and(|current| Weak::ptr_eq(&current, &self.control)) {
            return;
        }
        control.lock().unwrap().fail(message);
    }
}

static DISCOVERED: Mutex<Vec<ShareDevice>> = Mutex::new(Vec::new());
static CONNECTED: Mutex<Option<SocketAddr>> = Mutex::new(None);
static REFRESH: AtomicBool = AtomicBool::new(false);

/// The picker reads discovery results from memory; nothing is persisted.
pub(super) fn publish_devices(devices: Vec<ShareDevice>) -> anyhow::Result<()> {
    *DISCOVERED.lock().unwrap() = devices;
    Ok(())
}

pub(super) fn set_connected(target: Option<SocketAddr>) {
    *CONNECTED.lock().unwrap() = target;
}

pub(super) fn devices() -> Vec<ShareDevice> {
    let mut devices = DISCOVERED.lock().unwrap().clone();
    if let Some(endpoint) = *CONNECTED.lock().unwrap()
        && !devices.iter().any(|device| device.endpoint == endpoint)
    {
        devices.push(ShareDevice {
            name: "已连接的手机".into(),
            device_type: 1,
            endpoint,
        });
    }
    devices
}

pub(super) fn take_device_refresh() -> bool {
    REFRESH.swap(false, Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths() -> (std::path::PathBuf, Vec<PathBuf>) {
        let root = std::env::temp_dir().join(format!(
            "clip-linux-share-{:016x}",
            u64::from_ne_bytes(crate::private::random().unwrap())
        ));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("sample.txt");
        std::fs::write(&path, b"synthetic payload").unwrap();
        (root, vec![path])
    }

    fn target(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}").parse().unwrap()
    }

    #[test]
    fn a_task_is_claimed_once_and_only_by_its_target() {
        let (root, files) = paths();
        let queue = Arc::new(Queue::new());
        let share = queue.enqueue(files, target(1)).unwrap();
        assert_eq!(queue.pending_target(), Some(target(1)));
        assert!(queue.take_for(target(2)).is_none());
        let request = queue.take_for(target(1)).unwrap();
        assert!(queue.take_for(target(1)).is_none(), "claimed twice");
        assert_eq!(request.offer.read(0, 0).unwrap(), b"synthetic payload");
        assert!(request.exists());
        drop(request);
        drop(share);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cancellation_blocks_sending_and_releases_the_slot() {
        let (root, files) = paths();
        let queue = Arc::new(Queue::new());
        let share = queue.enqueue(files.clone(), target(1)).unwrap();
        let mut request = queue.take_for(target(1)).unwrap();
        share.cancel();
        assert!(!request.exists(), "cancelled task still accepts sends");
        assert!(request.status("sending", 4).is_ok());
        assert_eq!(share.snapshot().state, ShareState::Cancelled);
        // A fresh task is accepted once the cancelled one released the slot.
        let fresh = queue.enqueue(files, target(2)).unwrap();
        assert_eq!(queue.pending_target(), Some(target(2)));
        drop(fresh);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn terminal_states_never_regress() {
        let (root, files) = paths();
        let queue = Arc::new(Queue::new());
        let share = queue.enqueue(files, target(1)).unwrap();
        let mut request = queue.take_for(target(1)).unwrap();
        request.complete().unwrap();
        assert_eq!(share.snapshot().state, ShareState::Completed);
        assert_eq!(share.snapshot().sent, share.snapshot().total);
        request.fail("late error").unwrap();
        request.status("sending", 1).unwrap();
        assert_eq!(share.snapshot().state, ShareState::Completed);
        assert!(share.snapshot().message.is_none());
        drop(request);
        drop(share);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn status_reports_waiting_and_sending_progress() {
        let (root, files) = paths();
        let queue = Arc::new(Queue::new());
        let share = queue.enqueue(files, target(1)).unwrap();
        let mut request = queue.take_for(target(1)).unwrap();
        request.status("waiting", 0).unwrap();
        assert_eq!(share.snapshot().state, ShareState::Waiting);
        request.status("sending", 9).unwrap();
        assert_eq!(share.snapshot().state, ShareState::Sending);
        assert_eq!(share.snapshot().sent, 9);
        assert!(request.status("nonsense", 0).is_err());
        drop(request);
        drop(share);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_late_failure_of_a_cancelled_task_does_not_touch_its_successor() {
        let (root, files) = paths();
        let queue = Arc::new(Queue::new());
        let first = queue.enqueue(files.clone(), target(1)).unwrap();
        let scope = queue.failure_scope().unwrap();
        first.cancel();
        let second = queue.enqueue(files, target(1)).unwrap();
        scope.fail_if_pending("stale failure");
        assert_eq!(second.snapshot().state, ShareState::Connecting);
        assert!(second.snapshot().message.is_none());
        drop(second);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn an_outstanding_task_reports_busy() {
        let (root, files) = paths();
        let queue = Arc::new(Queue::new());
        let share = queue.enqueue(files.clone(), target(1)).unwrap();
        assert!(queue.enqueue(files.clone(), target(2)).is_err());
        share.cancel();
        assert!(queue.enqueue(files, target(2)).is_ok());
        std::fs::remove_dir_all(root).unwrap();
    }
}
