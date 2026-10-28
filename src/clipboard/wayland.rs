//! Native Wayland clipboard backend.
//!
//! Selection changes are observed through `ext-data-control` (preferred) or
//! `wlr-data-control`; X11/XWayland is never involved. The watcher runs on its
//! own thread so a source that neither writes nor closes its pipe can never
//! block the protocol loop, and every read has a hard deadline. Contents stay in
//! memory: no helper process, temporary file, or history database.
use super::{Content, Image, MAX_IMAGE_BYTES};
use std::{
    os::fd::AsFd,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
        mpsc::SyncSender,
    },
    time::{Duration, Instant},
};
use wl_clipboard_rs::{
    copy::{self, MimeSource, MimeType, Options, Source},
    paste::Seat as PasteSeat,
    watch::{CancelHandle, ClipboardEvent, ClipboardType, Offer as WatchOffer, Watcher},
};

/// Text and URI lists must arrive quickly; encoded images get a longer budget.
const TEXT_DEADLINE: Duration = Duration::from_secs(2);
const IMAGE_DEADLINE: Duration = Duration::from_secs(4);
/// Longest a cancellation request waits before the reader notices it.
const CANCEL_POLL: Duration = Duration::from_millis(100);
const MAX_URI_BYTES: usize = 64 * 1024;
const MAX_URI_FILES: usize = 128;
const URI_MIME: &str = "text/uri-list";
const IMAGE_MIMES: [(&str, &str); 4] = [
    ("image/png", "Clipboard.png"),
    ("image/jpeg", "Clipboard.jpg"),
    ("image/gif", "Clipboard.gif"),
    ("image/tiff", "Clipboard.tiff"),
];
/// Plain text fallbacks in the order the phone protocol understands them.
const TEXT_MIMES: [&str; 3] = ["text/plain;charset=utf-8", "text/plain", "UTF8_STRING"];

#[derive(Default)]
struct Latest {
    value: Option<Content>,
    error: Option<String>,
}

/// Change-driven reader. `poll` never blocks: the watcher thread publishes the
/// newest observable selection and surfaces connection errors explicitly.
pub struct Reader {
    latest: Arc<Mutex<Latest>>,
    cancel: CancelHandle,
    stopped: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Reader {
    pub fn open(reoffer_initial: bool) -> anyhow::Result<Self> {
        let seat = seat_name()?;
        let origin = origin_mime()?.to_owned();
        let latest = Arc::new(Mutex::new(Latest::default()));
        let stopped = Arc::new(AtomicBool::new(false));
        let (ready, ready_rx) = std::sync::mpsc::sync_channel(1);
        let thread = std::thread::Builder::new()
            .name("mi-clip-clipboard".into())
            .spawn({
                let latest = latest.clone();
                let stopped = stopped.clone();
                move || watch(seat, origin, reoffer_initial, latest, stopped, ready)
            })?;
        let cancel = ready_rx
            .recv()
            .map_err(|_| anyhow::anyhow!("Wayland 剪贴板监听线程未能启动"))?
            .map_err(protocol_error)?;
        Ok(Self {
            latest,
            cancel,
            stopped,
            thread: Some(thread),
        })
    }

    pub fn poll(&mut self) -> anyhow::Result<Option<Content>> {
        let mut latest = self.latest.lock().unwrap();
        if let Some(error) = latest.error.take() {
            return Err(anyhow::anyhow!(error));
        }
        Ok(latest.value.take())
    }

    pub fn write_text(&mut self, text: &str) -> anyhow::Result<()> {
        copy_text(text)
    }
}

impl Drop for Reader {
    fn drop(&mut self) {
        // Release this reader even if it is blocked inside a pipe read.
        self.stopped.store(true, Ordering::Relaxed);
        self.cancel.cancel();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn publish(latest: &Mutex<Latest>, content: Content) {
    latest.lock().unwrap().value = Some(content);
}

fn watch(
    seat: String,
    origin: String,
    reoffer_initial: bool,
    latest: Arc<Mutex<Latest>>,
    stopped: Arc<AtomicBool>,
    ready: SyncSender<Result<CancelHandle, wl_clipboard_rs::paste::Error>>,
) {
    let mut watcher = match Watcher::new(ClipboardType::Regular, PasteSeat::Specific(&seat)) {
        Ok(watcher) => watcher,
        Err(error) => {
            let _ = ready.send(Err(error));
            return;
        }
    };
    if ready.send(Ok(watcher.cancel_handle())).is_err() {
        return;
    }
    let mut baseline = true;
    loop {
        if stopped.load(Ordering::Relaxed) {
            break;
        }
        match watcher.next_event() {
            Ok(None) => break,
            Ok(Some(ClipboardEvent::Cleared { .. })) => {
                if !baseline {
                    publish(&latest, Content::Unsupported);
                }
                baseline = false;
            }
            Ok(Some(ClipboardEvent::Changed {
                mime_types,
                mut offer,
                ..
            })) => {
                let first = std::mem::replace(&mut baseline, false);
                if mime_types.iter().any(|mime| mime == &origin) {
                    // Our own write: revoke a stale offer, never echo text back.
                    publish(&latest, Content::Unsupported);
                    continue;
                }
                if first && !reoffer_initial {
                    // A resident session establishes a baseline: old text and
                    // files are not replayed, but the current image is reoffered.
                    if !mime_types.iter().any(|mime| mime.starts_with("image/")) {
                        continue;
                    }
                    if let Content::Image(image) =
                        parse_selection(&mut offer, &mime_types, &stopped)
                    {
                        publish(&latest, Content::Image(image));
                    }
                    continue;
                }
                // Revoke the previous offer before touching any pipe, so a slow
                // or hostile source can never keep an older file offer alive.
                publish(&latest, Content::Unsupported);
                publish(&latest, parse_selection(&mut offer, &mime_types, &stopped));
            }
            Err(error) => {
                latest.lock().unwrap().error = Some(format!("Wayland 剪贴板通信失败：{error}"));
                break;
            }
        }
    }
}

fn protocol_error(error: wl_clipboard_rs::paste::Error) -> anyhow::Error {
    if matches!(
        error,
        wl_clipboard_rs::paste::Error::MissingProtocol { .. }
            | wl_clipboard_rs::paste::Error::NoSeats
    ) {
        anyhow::anyhow!("Wayland 缺少 ext-data-control / wlr-data-control：{error}")
    } else {
        anyhow::anyhow!("Wayland 剪贴板不可用：{error}")
    }
}

fn copy_error(error: copy::Error) -> anyhow::Error {
    if matches!(
        error,
        copy::Error::MissingProtocol { .. } | copy::Error::NoSeats
    ) {
        anyhow::anyhow!("Wayland 缺少 ext-data-control / wlr-data-control：{error}")
    } else {
        anyhow::anyhow!("Wayland 剪贴板写入失败：{error}")
    }
}

/// The registry id of the first named seat, so both reading and writing address
/// the same seat. A seat without a name cannot be targeted safely.
fn seat_name() -> anyhow::Result<String> {
    use wayland_client::{
        Connection, Dispatch, QueueHandle,
        protocol::{wl_registry, wl_seat},
    };

    #[derive(Default)]
    struct Seats {
        globals: Vec<(u32, u32)>,
        names: Vec<(u32, String)>,
    }

    impl Dispatch<wl_registry::WlRegistry, ()> for Seats {
        fn event(
            state: &mut Self,
            _registry: &wl_registry::WlRegistry,
            event: wl_registry::Event,
            _data: &(),
            _connection: &Connection,
            _handle: &QueueHandle<Self>,
        ) {
            if let wl_registry::Event::Global {
                name,
                interface,
                version,
            } = event
                && interface == "wl_seat"
            {
                state.globals.push((name, version));
            }
        }
    }

    impl Dispatch<wl_seat::WlSeat, u32> for Seats {
        fn event(
            state: &mut Self,
            _seat: &wl_seat::WlSeat,
            event: wl_seat::Event,
            data: &u32,
            _connection: &Connection,
            _handle: &QueueHandle<Self>,
        ) {
            if let wl_seat::Event::Name { name } = event {
                state.names.push((*data, name));
            }
        }
    }

    let connection = Connection::connect_to_env()
        .map_err(|error| anyhow::anyhow!("无法连接 Wayland 合成器：{error}"))?;
    let mut queue = connection.new_event_queue::<Seats>();
    let handle = queue.handle();
    let registry = connection.display().get_registry(&handle, ());
    let mut seats = Seats::default();
    queue.roundtrip(&mut seats)?;
    let mut globals = seats.globals.clone();
    globals.sort_unstable();
    for (name, version) in globals {
        // The seat name event requires version 8; older seats cannot be named.
        if version < 8 {
            continue;
        }
        registry.bind::<wl_seat::WlSeat, u32, Seats>(name, 8, &handle, name);
    }
    queue.roundtrip(&mut seats)?;
    seats.names.sort_unstable();
    seats
        .names
        .into_iter()
        .next()
        .map(|(_, name)| name)
        .ok_or_else(|| anyhow::anyhow!("Wayland 会话没有可用命名的 seat，无法定向剪贴板操作"))
}

/// A per-process MIME type that marks our own selection. It carries no account,
/// installation, or clipboard data and is never persisted.
fn origin_mime() -> anyhow::Result<&'static str> {
    static ORIGIN: OnceLock<String> = OnceLock::new();
    if let Some(value) = ORIGIN.get() {
        return Ok(value.as_str());
    }
    let bytes = crate::private::random::<16>()?;
    let suffix: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    let value = format!("application/x-mi-clip-origin-{suffix}");
    Ok(ORIGIN.get_or_init(|| value).as_str())
}

/// Writes text for other applications to paste. The owner lives in library
/// threads and serves unlimited requests until this process exits.
pub(super) fn copy_text(text: &str) -> anyhow::Result<()> {
    let seat = seat_name()?;
    let origin = origin_mime()?.to_owned();
    let mut options = Options::new();
    options.seat(copy::Seat::Specific(seat));
    options
        .copy_multi(vec![
            MimeSource {
                source: Source::Bytes(text.as_bytes().into()),
                mime_type: MimeType::Text,
            },
            MimeSource {
                source: Source::Bytes(Box::default()),
                mime_type: MimeType::Specific(origin),
            },
        ])
        .map_err(copy_error)
}

/// One-shot diagnostic read of the current selection text.
pub(super) fn read_text() -> anyhow::Result<Option<String>> {
    let seat = seat_name()?;
    let mut watcher =
        Watcher::new(ClipboardType::Regular, PasteSeat::Specific(&seat)).map_err(protocol_error)?;
    let stopped = AtomicBool::new(false);
    match watcher.next_event().map_err(protocol_error)? {
        Some(ClipboardEvent::Changed {
            mime_types,
            mut offer,
            ..
        }) => {
            let Some(mime) = TEXT_MIMES
                .iter()
                .find(|mime| mime_types.iter().any(|offered| offered == *mime))
            else {
                return Ok(None);
            };
            let bytes = read_mime(
                &mut offer,
                mime,
                crate::message_center::MAX_INLINE_TEXT,
                TEXT_DEADLINE,
                &stopped,
            )?;
            Ok(String::from_utf8(bytes)
                .ok()
                .filter(|text| !text.is_empty()))
        }
        _ => Ok(None),
    }
}

fn parse_selection(
    offer: &mut WatchOffer<'_>,
    mime_types: &[String],
    stopped: &AtomicBool,
) -> Content {
    // A file representation always wins; a failed file read never falls back
    // to accompanying text, which would leak a filename as clipboard text.
    if mime_types.iter().any(|mime| mime == URI_MIME) {
        return match read_mime(offer, URI_MIME, MAX_URI_BYTES, TEXT_DEADLINE, stopped)
            .and_then(|bytes| parse_uri_list(&bytes))
        {
            Ok(paths) => Content::Files(paths),
            // A failed or oversized file representation never falls back to text.
            Err(_) => Content::Unsupported,
        };
    }
    // The same is true for any image representation.
    if mime_types.iter().any(|mime| mime.starts_with("image/")) {
        return read_image(offer, mime_types, stopped).unwrap_or(Content::Unsupported);
    }
    let Some(mime) = TEXT_MIMES
        .iter()
        .find(|mime| mime_types.iter().any(|offered| offered == *mime))
    else {
        return Content::Unsupported;
    };
    match read_mime(
        offer,
        mime,
        crate::message_center::MAX_INLINE_TEXT,
        TEXT_DEADLINE,
        stopped,
    ) {
        Ok(bytes) => match String::from_utf8(bytes) {
            Ok(text) if !text.is_empty() => Content::Text(text),
            _ => Content::Unsupported,
        },
        Err(_) => Content::Unsupported,
    }
}

fn read_image(
    offer: &mut WatchOffer<'_>,
    mime_types: &[String],
    stopped: &AtomicBool,
) -> Option<Content> {
    for (mime, name) in IMAGE_MIMES {
        if !mime_types.iter().any(|offered| offered == mime) {
            continue;
        }
        let bytes = read_mime(offer, mime, MAX_IMAGE_BYTES, IMAGE_DEADLINE, stopped).ok()?;
        if bytes.is_empty() {
            return None;
        }
        return Some(Content::Image(Image { name, bytes }));
    }
    None
}

fn read_mime(
    offer: &mut WatchOffer<'_>,
    mime: &str,
    limit: usize,
    deadline: Duration,
    stopped: &AtomicBool,
) -> anyhow::Result<Vec<u8>> {
    let pipe = offer.receive(mime).map_err(protocol_error)?;
    read_fd(pipe, limit, deadline, stopped)
}

/// Reads at most `limit` bytes before `deadline`; the deadline is absolute, so
/// a slow trickle cannot extend it. The read side is switched to non-blocking
/// and only read after `poll` reports readiness.
fn read_fd(
    fd: impl AsFd,
    limit: usize,
    deadline: Duration,
    stopped: &AtomicBool,
) -> anyhow::Result<Vec<u8>> {
    use rustix::{
        event::{PollFd, PollFlags, Timespec, poll},
        fs::OFlags,
        io::Errno,
    };
    let flags = rustix::fs::fcntl_getfl(&fd)?;
    rustix::fs::fcntl_setfl(&fd, flags | OFlags::NONBLOCK)?;
    let start = Instant::now();
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 16384];
    loop {
        anyhow::ensure!(!stopped.load(Ordering::Relaxed), "Clipboard reader stopped");
        let elapsed = start.elapsed();
        anyhow::ensure!(elapsed < deadline, "Clipboard content read timed out");
        let wait = (deadline - elapsed).min(CANCEL_POLL);
        let wait = Timespec::try_from(wait)
            .map_err(|_| anyhow::anyhow!("Invalid clipboard read deadline"))?;
        let mut fds = [PollFd::new(&fd, PollFlags::IN)];
        match poll(&mut fds, Some(&wait)) {
            Ok(_) => (),
            Err(Errno::INTR) => continue,
            Err(error) => return Err(error.into()),
        }
        if fds[0].revents().is_empty() {
            continue;
        }
        match rustix::io::read(&fd, &mut buffer) {
            Ok(0) => return Ok(bytes),
            Ok(count) => {
                bytes.extend_from_slice(&buffer[..count]);
                anyhow::ensure!(
                    bytes.len() <= limit,
                    "Clipboard content exceeds the size limit"
                );
            }
            Err(Errno::WOULDBLOCK) | Err(Errno::INTR) => continue,
            Err(error) => return Err(error.into()),
        }
    }
}

/// Parses a `text/uri-list` body: CRLF lines, `#` comments, local file URLs only.
fn parse_uri_list(bytes: &[u8]) -> anyhow::Result<Vec<std::path::PathBuf>> {
    anyhow::ensure!(
        bytes.len() <= MAX_URI_BYTES,
        "Clipboard URI list exceeds the size limit"
    );
    let text = std::str::from_utf8(bytes)
        .map_err(|_| anyhow::anyhow!("Clipboard URI list is not UTF-8"))?;
    let mut paths = Vec::new();
    for line in text.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let url = url::Url::parse(line)
            .map_err(|_| anyhow::anyhow!("Clipboard contains an invalid URI"))?;
        anyhow::ensure!(url.scheme() == "file", "Clipboard URI is not a local file");
        anyhow::ensure!(
            url.host_str()
                .is_none_or(|host| host.is_empty() || host == "localhost"),
            "Clipboard URI names a remote host"
        );
        let path = url
            .to_file_path()
            .map_err(|_| anyhow::anyhow!("Clipboard URI has no usable path"))?;
        anyhow::ensure!(
            !path.as_os_str().as_encoded_bytes().contains(&0),
            "Clipboard path contains a NUL byte"
        );
        anyhow::ensure!(
            paths.len() < MAX_URI_FILES,
            "Clipboard file offer exceeds the item limit"
        );
        paths.push(path);
    }
    anyhow::ensure!(!paths.is_empty(), "Clipboard URI list is empty");
    Ok(paths)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("mi-clip-uri-{name}"))
    }

    #[test]
    fn uri_lists_accept_crlf_comments_and_percent_encoding() {
        let first = temp_path("first file.bin");
        let second = temp_path("正常.txt");
        let body = format!(
            "# comment\r\nfile://{}\r\n\r\nfile://localhost{}\r\n",
            first.display(),
            second.display()
        );
        // The url crate rejects a raw space, so encode like a real selection manager.
        let body = body.replace(' ', "%20");
        let paths = parse_uri_list(body.as_bytes()).unwrap();
        assert_eq!(paths, vec![first, second]);
    }

    #[test]
    fn remote_hosts_other_schemes_and_empty_lists_are_rejected() {
        for body in [
            "https://example.invalid/file.bin",
            "file://remote.invalid/tmp/x.bin",
            "# only a comment\n",
            "",
        ] {
            assert!(parse_uri_list(body.as_bytes()).is_err(), "{body}");
        }
    }

    #[test]
    fn nul_bytes_and_item_overflow_are_rejected() {
        assert!(parse_uri_list(b"file:///tmp/a%00b").is_err());
        let mut body = String::new();
        for index in 0..=MAX_URI_FILES {
            body.push_str(&format!("file:///tmp/file-{index}\n"));
        }
        assert!(parse_uri_list(body.as_bytes()).is_err());
        let oversized = format!("file:///tmp/{}\n", "x".repeat(MAX_URI_BYTES));
        assert!(parse_uri_list(oversized.as_bytes()).is_err());
    }

    #[test]
    fn reads_stop_at_the_deadline_without_writer_progress() {
        use std::io::Write;
        use std::os::unix::net::UnixStream;
        let stopped = AtomicBool::new(false);
        // A writer that stays open without sending anything must not hang us.
        let (reader, mut writer) = UnixStream::pair().unwrap();
        let started = Instant::now();
        let result = read_fd(&reader, 16, Duration::from_millis(150), &stopped);
        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_secs(2));
        writer.write_all(b"payload").unwrap();
        drop(writer);
        let (reader, _) = UnixStream::pair().unwrap();
        let _ = reader;
        // Oversized content is rejected rather than truncated.
        let (reader, mut writer) = UnixStream::pair().unwrap();
        writer.write_all(&[7u8; 64]).unwrap();
        drop(writer);
        assert!(read_fd(&reader, 8, Duration::from_millis(500), &stopped).is_err());
        // Cancellation releases a blocked read well before the deadline.
        let (reader, _writer) = UnixStream::pair().unwrap();
        let cancel = Arc::new(AtomicBool::new(false));
        let signal = cancel.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            signal.store(true, Ordering::Relaxed);
        });
        let started = Instant::now();
        assert!(read_fd(&reader, 16, Duration::from_secs(5), &cancel).is_err());
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn origin_types_are_stable_and_do_not_leak_data() {
        let first = origin_mime().unwrap().to_owned();
        let second = origin_mime().unwrap().to_owned();
        assert_eq!(first, second);
        assert!(first.starts_with("application/x-mi-clip-origin-"));
        let suffix = &first["application/x-mi-clip-origin-".len()..];
        assert_eq!(suffix.len(), 32);
        assert!(
            suffix
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        );
    }

    /// Needs a real compositor; run through the private headless harness.
    #[test]
    #[ignore]
    fn native_selection_round_trip() {
        /// First non-revocation content; `Unsupported` alone means no business
        /// content arrived (the reader revokes an older offer before parsing).
        fn wait(reader: &mut Reader) -> Option<Content> {
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline {
                match reader.poll() {
                    Ok(Some(Content::Unsupported)) => (),
                    Ok(Some(content)) => return Some(content),
                    Ok(None) => (),
                    Err(error) => panic!("clipboard reader failed: {error:#}"),
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            None
        }
        fn selection(sources: Vec<MimeSource>) -> Option<Content> {
            let mut options = Options::new();
            options.seat(copy::Seat::Specific(seat_name().unwrap()));
            options.copy_multi(sources).unwrap();
            // Let the compositor publish the new selection before the watcher
            // establishes its baseline, so the first content is the new one.
            std::thread::sleep(Duration::from_millis(300));
            let mut reader = Reader::open(true).unwrap();
            wait(&mut reader)
        }
        let bytes = |value: &str| Source::Bytes(value.as_bytes().into());
        let text = || MimeSource {
            source: bytes("accompanying text"),
            mime_type: MimeType::Text,
        };

        // An independent owner (wl-copy) is read like any foreign selection.
        if std::process::Command::new("wl-copy")
            .arg("--version")
            .output()
            .is_ok_and(|output| output.status.success())
        {
            let status = std::process::Command::new("wl-copy")
                .arg("外部文本")
                .status()
                .unwrap();
            assert!(status.success(), "wl-copy failed");
            // The forked owner may publish a moment after wl-copy exits.
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut observed = None;
            while Instant::now() < deadline {
                if let Some(text) = read_text().unwrap()
                    && text == "外部文本"
                {
                    observed = Some(text);
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            assert_eq!(
                observed.as_deref(),
                Some("外部文本"),
                "foreign wl-copy selection was not readable"
            );
        }
        // Independent text round trip and selection replacement.
        copy_text("first 文本").unwrap();
        assert_eq!(read_text().unwrap().as_deref(), Some("first 文本"));
        copy_text("second").unwrap();
        assert_eq!(read_text().unwrap().as_deref(), Some("second"));
        // Our own selection only ever produces a revocation, never text.
        {
            let mut reader = Reader::open(true).unwrap();
            assert!(wait(&mut reader).is_none());
        }
        // The copy owner still serves text after the reader is gone.
        assert_eq!(read_text().unwrap().as_deref(), Some("second"));

        // A URI list wins over accompanying text.
        let first = temp_path("selection.bin");
        let second = temp_path("second selection.txt");
        std::fs::write(&first, b"synthetic").unwrap();
        std::fs::write(&second, b"").unwrap();
        let body = format!(
            "file://{}\r\nfile://{}\r\n",
            first.display(),
            second.display()
        )
        .replace(' ', "%20");
        let observed = selection(vec![
            MimeSource {
                source: bytes(&body),
                mime_type: MimeType::Specific(URI_MIME.into()),
            },
            text(),
        ]);
        assert!(
            matches!(
                &observed,
                Some(Content::Files(paths)) if *paths == vec![first.clone(), second.clone()]
            ),
            "URI selection did not win over text"
        );

        // An image wins over accompanying text, byte for byte.
        let mut png = Vec::new();
        {
            let mut encoder = png::Encoder::new(&mut png, 1, 1);
            encoder.set_color(png::ColorType::Rgba);
            encoder.set_depth(png::BitDepth::Eight);
            encoder
                .write_header()
                .unwrap()
                .write_image_data(&[10, 20, 30, 255])
                .unwrap();
        }
        assert!(matches!(
            selection(vec![
                MimeSource {
                    source: Source::Bytes(png.clone().into()),
                    mime_type: MimeType::Specific("image/png".into()),
                },
                text(),
            ]),
            Some(Content::Image(image)) if image.bytes == png && image.name == "Clipboard.png"
        ));

        // An unsupported image representation never degrades to accompanying text.
        assert!(
            selection(vec![
                MimeSource {
                    source: bytes("not an image"),
                    mime_type: MimeType::Specific("image/webp".into()),
                },
                text(),
            ])
            .is_none(),
            "unsupported image fell back to text"
        );
        std::fs::remove_file(&first).unwrap();
        std::fs::remove_file(&second).unwrap();
    }
}
