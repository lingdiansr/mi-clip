//! Anonymous, best-effort usage events delivered by the official PostHog SDK.
use posthog_rs::{Client, ClientOptionsBuilder};
use serde_json::json;
use std::{
    path::{Path, PathBuf},
    sync::OnceLock,
};

// Public ingestion token shared with CNote and cyeam-cli; never use a personal API key here.
const PROJECT_TOKEN: &str = "phc_kBqNf6Fx4wEaDzDthoJBqvbVVRCVZZ5Pk8CbeZK49RBp";
const CAPACITY: usize = 128;
struct Tracker {
    client: Client,
    id: String,
}
static TRACKER: OnceLock<Tracker> = OnceLock::new();

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Started,
    Success,
    Failure,
    Skipped,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    Discovery,
    Connect,
    Authenticate,
    Session,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Send,
    Receive,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Text,
    File,
    Image,
    Unknown,
}
#[derive(Debug)]
pub enum Event {
    Started,
    Connection {
        outcome: Outcome,
        stage: Stage,
        duration_ms: u64,
    },
    Clipboard {
        direction: Direction,
        kind: Kind,
        outcome: Outcome,
        bytes: Option<usize>,
        files: Option<u32>,
    },
    Share {
        outcome: Outcome,
        files: Option<u32>,
        duration_ms: u64,
    },
    Receive {
        outcome: Outcome,
        files: Option<u32>,
        duration_ms: u64,
    },
}
fn outcome(value: Outcome) -> &'static str {
    match value {
        Outcome::Started => "started",
        Outcome::Success => "success",
        Outcome::Failure => "failure",
        Outcome::Skipped => "skipped",
    }
}
fn sdk_event(id: &str, event: &Event) -> posthog_rs::Event {
    let mut props = json!({
        "app": "mi-clip", "platform": std::env::consts::OS, "app_version": env!("CARGO_PKG_VERSION"),
        "os": std::env::consts::OS, "architecture": std::env::consts::ARCH,
        "$process_person_profile": false
    });
    let name = match event {
        Event::Started => "app_started",
        Event::Connection {
            outcome: result,
            stage,
            duration_ms,
        } => {
            props["outcome"] = json!(outcome(*result));
            props["stage"] = json!(match stage {
                Stage::Discovery => "discovery",
                Stage::Connect => "connect",
                Stage::Authenticate => "authenticate",
                Stage::Session => "session",
            });
            props["duration_ms"] = json!(duration_ms);
            "connection_completed"
        }
        Event::Clipboard {
            direction,
            kind,
            outcome: result,
            bytes,
            files,
        } => {
            props["direction"] = json!(match direction {
                Direction::Send => "send",
                Direction::Receive => "receive",
            });
            props["content_type"] = json!(match kind {
                Kind::Text => "text",
                Kind::File => "file",
                Kind::Image => "image",
                Kind::Unknown => "unknown",
            });
            props["outcome"] = json!(outcome(*result));
            if let Some(bytes) = bytes {
                props["bytes"] = json!(bytes);
            }
            if let Some(files) = files {
                props["files"] = json!(files);
            }
            "clipboard_sync_completed"
        }
        Event::Share {
            outcome: result,
            files,
            duration_ms,
        }
        | Event::Receive {
            outcome: result,
            files,
            duration_ms,
        } => {
            props["outcome"] = json!(outcome(*result));
            props["duration_ms"] = json!(duration_ms);
            if let Some(files) = files {
                props["files"] = json!(files);
            }
            match (event, result) {
                (Event::Share { .. }, Outcome::Started) => "file_share_started",
                (Event::Share { .. }, _) => "file_share_completed",
                (_, Outcome::Started) => "file_receive_started",
                _ => "file_receive_completed",
            }
        }
    };
    let mut event = posthog_rs::Event::new(name, id);
    for (key, value) in props.as_object().expect("event properties are an object") {
        event
            .insert_prop(key, value)
            .expect("JSON values are serializable");
    }
    event
}
fn truthy(value: &str) -> bool {
    matches!(value.to_ascii_lowercase().as_str(), "1" | "true" | "yes")
}
fn disabled() -> bool {
    cfg!(test)
        || [
            "MICLIP_NO_ANALYTICS",
            "DO_NOT_TRACK",
            "CI",
            "MICLIP_SMOKE_TEST",
        ]
        .iter()
        .any(|key| std::env::var(key).is_ok_and(|v| truthy(&v)))
        || (cfg!(debug_assertions)
            && !std::env::var("MICLIP_ANALYTICS_DEBUG").is_ok_and(|v| truthy(&v)))
}

fn client_options() -> ClientOptionsBuilder {
    let mut options = ClientOptionsBuilder::default();
    options
        .api_key(PROJECT_TOKEN.to_owned())
        .is_server(false)
        .max_queue_size(CAPACITY)
        .request_timeout_seconds(5)
        .shutdown_timeout_ms(1000)
        .on_error(|_| eprintln!("Clip: anonymous usage upload failed"));
    options
}

pub fn start(directory: PathBuf) {
    if disabled() {
        return;
    }
    TRACKER.get_or_init(|| {
        let tracker = Tracker {
            client: posthog_rs::client(client_options().build().expect("valid PostHog options")),
            id: installation_id(&directory),
        };
        tracker
            .client
            .capture(sdk_event(&tracker.id, &Event::Started));
        tracker
    });
}
pub fn capture(event: Event) {
    if let Some(tracker) = TRACKER.get() {
        // The SDK queues and sends on its own bounded background worker.
        tracker.client.capture(sdk_event(&tracker.id, &event));
    }
}
pub fn shutdown() {
    if let Some(tracker) = TRACKER.get() {
        // Native quit hook: drain best-effort with bounded network timeouts.
        tracker.client.shutdown();
    }
}
fn installation_id(directory: &Path) -> String {
    let path = directory.join("analytics-id");
    let read = || {
        std::fs::read_to_string(&path)
            .ok()
            .filter(|v| uuid::Uuid::parse_str(v).is_ok())
    };
    if let Some(id) = read() {
        return format!("mi-clip:{id}");
    }
    let id = uuid::Uuid::new_v4().to_string();
    let temp = directory.join(format!(".analytics-{}", uuid::Uuid::new_v4()));
    let write = || -> std::io::Result<()> {
        use std::io::Write;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temp)?;
        file.write_all(id.as_bytes())?;
        // Atomic publication: concurrent starts read the same complete ID.
        std::fs::hard_link(&temp, &path)?;
        Ok(())
    };
    let _ = write();
    let _ = std::fs::remove_file(temp);
    format!("mi-clip:{}", read().unwrap_or(id))
}

/// Observe semantic worker events, never clipboard values or peer/config data.
/// Consecutive failures in the same connection phase are counted once until
/// a connection succeeds, so an offline phone cannot flood the event queue.
#[cfg(feature = "clipboard")]
pub struct Session {
    started: std::time::Instant,
    stage: Stage,
    last_failure: Option<Stage>,
    share: Option<std::time::Instant>,
    receive: Option<std::time::Instant>,
    clipboard_kind: Kind,
    clipboard_pull: bool,
}
#[cfg(feature = "clipboard")]
impl Default for Session {
    fn default() -> Self {
        Self {
            started: std::time::Instant::now(),
            stage: Stage::Discovery,
            last_failure: None,
            share: None,
            receive: None,
            clipboard_kind: Kind::File,
            clipboard_pull: false,
        }
    }
}
#[cfg(feature = "clipboard")]
impl Session {
    pub fn begin(&mut self) {
        self.started = std::time::Instant::now();
        self.stage = Stage::Discovery;
        self.share = None;
        self.receive = None;
        self.clipboard_pull = false;
    }
    pub fn observe(&mut self, event: &crate::handshake::SyncEvent) -> Option<Event> {
        use crate::{file_feedback::Event as F, handshake::SyncEvent as S};
        let clipboard = |direction, kind, result, bytes, files| Event::Clipboard {
            direction,
            kind,
            outcome: result,
            bytes,
            files,
        };
        match event {
            S::Connecting(_) => self.stage = Stage::Connect,
            S::Authenticating => self.stage = Stage::Authenticate,
            S::Connected => {
                self.stage = Stage::Session;
                self.last_failure = None;
                return Some(Event::Connection {
                    outcome: Outcome::Success,
                    stage: self.stage,
                    duration_ms: elapsed(self.started),
                });
            }
            S::Sent(bytes) => {
                return Some(clipboard(
                    Direction::Send,
                    Kind::Text,
                    Outcome::Success,
                    Some(*bytes),
                    None,
                ));
            }
            S::Received(bytes) => {
                return Some(clipboard(
                    Direction::Receive,
                    Kind::Text,
                    Outcome::Success,
                    Some(*bytes),
                    None,
                ));
            }
            S::FileClipboardOffered(_) => self.clipboard_kind = Kind::File,
            S::ImageClipboardOffered => self.clipboard_kind = Kind::Image,
            S::FileClipboardRequested => self.clipboard_pull = true,
            S::FileClipboardSent(files) if self.clipboard_pull => {
                self.clipboard_pull = false;
                return Some(clipboard(
                    Direction::Send,
                    self.clipboard_kind,
                    Outcome::Success,
                    None,
                    Some(*files),
                ));
            }
            S::FileClipboardFailed if self.clipboard_pull => {
                self.clipboard_pull = false;
                return Some(clipboard(
                    Direction::Send,
                    self.clipboard_kind,
                    Outcome::Failure,
                    None,
                    None,
                ));
            }
            S::FileClipboardSkipped => {
                return Some(clipboard(
                    Direction::Send,
                    Kind::File,
                    Outcome::Skipped,
                    None,
                    None,
                ));
            }
            S::Unsupported => {
                return Some(clipboard(
                    Direction::Send,
                    Kind::Text,
                    Outcome::Skipped,
                    None,
                    None,
                ));
            }
            S::UnsupportedClipboard => {
                return Some(clipboard(
                    Direction::Receive,
                    Kind::Unknown,
                    Outcome::Skipped,
                    None,
                    None,
                ));
            }
            S::ShareStarted if self.share.is_none() => {
                self.share = Some(std::time::Instant::now());
                return Some(Event::Share {
                    outcome: Outcome::Started,
                    files: None,
                    duration_ms: 0,
                });
            }
            S::ShareCompleted(files) => {
                return self.share.take().map(|started| Event::Share {
                    outcome: Outcome::Success,
                    files: Some(*files),
                    duration_ms: elapsed(started),
                });
            }
            S::ShareFailed => {
                return self.share.take().map(|started| Event::Share {
                    outcome: Outcome::Failure,
                    files: None,
                    duration_ms: elapsed(started),
                });
            }
            S::File(F::Requested) if self.receive.is_none() => {
                self.receive = Some(std::time::Instant::now());
                return Some(Event::Receive {
                    outcome: Outcome::Started,
                    files: None,
                    duration_ms: 0,
                });
            }
            S::File(F::Saved { files }) => {
                return self.receive.take().map(|started| Event::Receive {
                    outcome: Outcome::Success,
                    files: Some(*files),
                    duration_ms: elapsed(started),
                });
            }
            S::File(F::Failed(_)) => {
                return self.receive.take().map(|started| Event::Receive {
                    outcome: Outcome::Failure,
                    files: None,
                    duration_ms: elapsed(started),
                });
            }
            _ => (),
        }
        None
    }
    pub fn failed(&mut self) -> Vec<Event> {
        let mut events = Vec::new();
        if self.last_failure != Some(self.stage) {
            events.push(Event::Connection {
                outcome: Outcome::Failure,
                stage: self.stage,
                duration_ms: elapsed(self.started),
            });
            self.last_failure = Some(self.stage);
        }
        if let Some(started) = self.share.take() {
            events.push(Event::Share {
                outcome: Outcome::Failure,
                files: None,
                duration_ms: elapsed(started),
            });
        }
        if let Some(started) = self.receive.take() {
            events.push(Event::Receive {
                outcome: Outcome::Failure,
                files: None,
                duration_ms: elapsed(started),
            });
        }
        if std::mem::take(&mut self.clipboard_pull) {
            events.push(Event::Clipboard {
                direction: Direction::Send,
                kind: self.clipboard_kind,
                outcome: Outcome::Failure,
                bytes: None,
                files: None,
            });
        }
        events
    }
}
#[cfg(feature = "clipboard")]
fn elapsed(started: std::time::Instant) -> u64 {
    started.elapsed().as_millis().min(u64::MAX as u128) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    fn directory() -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("miclip-analytics-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        dir
    }
    #[test]
    fn anonymous_id_is_stable_private_and_shared_by_concurrent_starts() {
        use std::os::unix::fs::PermissionsExt;
        let dir = directory();
        let ids = std::thread::scope(|s| {
            (0..12)
                .map(|_| s.spawn(|| installation_id(&dir)))
                .collect::<Vec<_>>()
                .into_iter()
                .map(|t| t.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert!(ids.iter().all(|id| id == &ids[0]));
        assert!(ids[0].starts_with("mi-clip:"));
        assert!(uuid::Uuid::parse_str(ids[0].strip_prefix("mi-clip:").unwrap()).is_ok());
        assert_eq!(
            std::fs::metadata(dir.join("analytics-id"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let other = directory();
        assert_ne!(ids[0], installation_id(&other));
        std::fs::remove_dir_all(dir).unwrap();
        std::fs::remove_dir_all(other).unwrap();
    }
    #[test]
    fn tests_never_initialize_or_send_telemetry() {
        assert!(disabled());
        start(PathBuf::from("/unused/test-data"));
        capture(Event::Started);
        shutdown();
        assert!(TRACKER.get().is_none());
    }
    #[test]
    fn payloads_only_contain_allowlisted_non_content_properties() {
        let events = [
            Event::Started,
            Event::Connection {
                outcome: Outcome::Failure,
                stage: Stage::Authenticate,
                duration_ms: 42,
            },
            Event::Clipboard {
                direction: Direction::Send,
                kind: Kind::Image,
                outcome: Outcome::Success,
                bytes: None,
                files: Some(1),
            },
            Event::Share {
                outcome: Outcome::Started,
                files: None,
                duration_ms: 0,
            },
            Event::Share {
                outcome: Outcome::Success,
                files: Some(2),
                duration_ms: 100,
            },
            Event::Receive {
                outcome: Outcome::Started,
                files: None,
                duration_ms: 0,
            },
            Event::Receive {
                outcome: Outcome::Failure,
                files: None,
                duration_ms: 12,
            },
        ];
        for (input, name) in events.iter().zip([
            "app_started",
            "connection_completed",
            "clipboard_sync_completed",
            "file_share_started",
            "file_share_completed",
            "file_receive_started",
            "file_receive_completed",
        ]) {
            let event = sdk_event("mi-clip:synthetic", input);
            assert_eq!(event.event_name(), name);
            assert_eq!(event.distinct_id(), "mi-clip:synthetic");
            let props = event.properties();
            assert_eq!(props["app"], "mi-clip");
            assert_eq!(props["app_version"], env!("CARGO_PKG_VERSION"));
            assert_eq!(props["$process_person_profile"], false);
            assert!(props.keys().all(|key| {
                [
                    "app",
                    "platform",
                    "app_version",
                    "os",
                    "architecture",
                    "$process_person_profile",
                    "outcome",
                    "stage",
                    "duration_ms",
                    "direction",
                    "content_type",
                    "bytes",
                    "files",
                ]
                .contains(&key.as_str())
            }));
        }
    }
    #[cfg(feature = "clipboard")]
    #[test]
    fn worker_events_record_confirmed_results_once_and_deduplicate_offline_retries() {
        use crate::{file_feedback::Event as F, handshake::SyncEvent as S};
        let mut session = Session::default();
        assert!(session.observe(&S::FileClipboardOffered(2)).is_none());
        assert!(session.observe(&S::FileClipboardRequested).is_none());
        assert!(matches!(
            session.observe(&S::FileClipboardSent(2)),
            Some(Event::Clipboard {
                outcome: Outcome::Success,
                files: Some(2),
                ..
            })
        ));
        assert!(session.observe(&S::FileClipboardSent(2)).is_none());
        assert!(session.observe(&S::ShareCompleted(2)).is_none());
        assert!(matches!(
            session.observe(&S::ShareStarted),
            Some(Event::Share {
                outcome: Outcome::Started,
                ..
            })
        ));
        assert!(matches!(
            session.observe(&S::ShareCompleted(2)),
            Some(Event::Share {
                outcome: Outcome::Success,
                files: Some(2),
                ..
            })
        ));
        assert!(session.observe(&S::ShareFailed).is_none());
        assert!(session.observe(&S::File(F::Saved { files: 1 })).is_none());
        session.observe(&S::File(F::Requested));
        let failed = session.failed();
        assert!(failed.iter().any(|e| matches!(
            e,
            Event::Receive {
                outcome: Outcome::Failure,
                ..
            }
        )));
        session.begin();
        assert!(session.failed().is_empty());
        session.observe(&S::Authenticating);
        assert_eq!(session.failed().len(), 1);
        session.observe(&S::Connected);
        assert_eq!(session.failed().len(), 1);
        assert!(session.failed().is_empty());
    }
    #[test]
    fn sdk_capture_drains_to_http_on_shutdown() {
        use std::{
            io::{BufRead, BufReader, Read, Write},
            time::{Duration, Instant},
        };
        let server = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        server.set_nonblocking(true).unwrap();
        let host = format!("http://{}", server.local_addr().unwrap());
        let received = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            let stream = loop {
                match server.accept() {
                    Ok((stream, _)) => break stream,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "SDK did not send queued event");
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(e) => panic!("accept: {e}"),
                }
            };
            // macOS may inherit O_NONBLOCK from the listener. A read timeout
            // does not clear it, so reading before the SDK writes can fail immediately.
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            assert!(line.starts_with("POST /batch/ "));
            let mut length = None;
            let mut sdk_user_agent = false;
            loop {
                line.clear();
                assert!(reader.read_line(&mut line).unwrap() > 0);
                if line == "\r\n" {
                    break;
                }
                let lower = line.to_ascii_lowercase();
                if let Some(value) = lower.strip_prefix("content-length:") {
                    length = Some(value.trim().parse::<usize>().unwrap());
                }
                sdk_user_agent |= lower.starts_with("user-agent: posthog-rs/");
            }
            assert!(sdk_user_agent);
            let mut bytes = vec![0; length.unwrap()];
            reader.read_exact(&mut bytes).unwrap();
            reader.get_mut().write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 15\r\nConnection: close\r\n\r\n{\"status\":\"Ok\"}").unwrap();
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()
        });
        let client = posthog_rs::client(client_options().host(host).build().unwrap());
        client.capture(sdk_event("mi-clip:local-test", &Event::Started));
        client.shutdown();
        let body = received.join().unwrap();
        assert_eq!(body["api_key"], PROJECT_TOKEN);
        assert_eq!(body["batch"].as_array().unwrap().len(), 1);
        let event = &body["batch"][0];
        assert_eq!(event["distinct_id"], "mi-clip:local-test");
        assert_eq!(event["event"], "app_started");
        assert_eq!(event["properties"]["app"], "mi-clip");
        assert_eq!(event["properties"]["$process_person_profile"], false);
        assert_ne!(event["properties"]["$is_server"], true);
        assert_eq!(event["properties"]["$lib"], "posthog-rs");
        assert!(uuid::Uuid::parse_str(event["uuid"].as_str().unwrap()).is_ok());
        assert!(event["timestamp"].is_string());
    }
    #[test]
    #[ignore = "sends a marked diagnostic event to the real PostHog project"]
    fn live_sdk_capture() {
        let client = posthog_rs::client(client_options().build().unwrap());
        let id = format!("mi-clip:diagnostic:{}", uuid::Uuid::new_v4());
        let mut event = sdk_event(&id, &Event::Started);
        event.insert_prop("integration_test", true).unwrap();
        event
            .insert_prop("diagnostic", "clip-posthog-integration")
            .unwrap();
        println!("PostHog diagnostic ID: {id}");
        let result = client.capture_immediate(event);
        client.shutdown();
        let summary = result.unwrap_or_else(|_| panic!("PostHog diagnostic delivery failed"));
        assert_eq!(summary.submitted(), 1);
        assert!(summary.all_persisted());
    }
}
