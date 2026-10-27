//! File-channel control messages. File bytes never travel through this parser.
use crate::wire::{self, Field};
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use p256::ecdsa::{SigningKey, signature::Signer};
use sha2::{Digest, Sha256};

fn bytes(input: &[u8], field: u32) -> anyhow::Result<&[u8]> {
    wire::bytes_field(input, field)
        .ok_or_else(|| anyhow::anyhow!("Missing file-channel byte field {field}"))
}
fn number(input: &[u8], field: u32) -> Option<u64> {
    wire::fields(input)?.into_iter().find_map(|f| match f {
        Field::Integer(n, v) if n == field => Some(v),
        _ => None,
    })
}

pub(crate) struct Incoming {
    pub peer_id: u8,
    pub nonce: u32,
    pub service: &'static str,
}

pub(crate) const SHARE_SERVICE: &str = "com.xiaomi.hyperConnect:miLyraShareTransfer";
// A connection names the service on its recipient. Android advertises the
// transfer service under its Mi Share package, not the Mac package above.
pub(crate) const PHONE_SHARE_SERVICE: &str = "com.miui.mishare.connectivity:miLyraShareTransfer";
pub(crate) fn clipboard_service(service: &str) -> bool {
    matches!(
        service,
        "com.xiaomi.hyperConnect:universalClipboard" | "com.milink.service:universalClipboard"
    )
}

#[cfg(test)]
pub(crate) fn sync_reply(
    key: &[u8; 32],
    signing: &SigningKey,
    uid: &str,
) -> anyhow::Result<Vec<u8>> {
    sync_reply_for_service(key, signing, uid, SHARE_SERVICE)
}
pub(crate) fn sync_reply_for_service(
    key: &[u8; 32],
    signing: &SigningKey,
    uid: &str,
    service: &str,
) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(
        service == SHARE_SERVICE || service == PHONE_SHARE_SERVICE || clipboard_service(service),
        "Unsupported local service"
    );
    use crate::wire::{integer, message};
    let challenge = crate::private::random::<32>()?;
    let signature: Signature = signing.sign(&challenge);
    let mut proof = message(1, &challenge);
    proof.extend(message(2, signature.to_der().as_bytes()));
    let mut credential = integer(1, 2);
    credential.extend(message(3, &proof));
    let mut group = integer(1, 1);
    group.extend(message(3, &credential));
    let iv = crate::private::random::<12>()?;
    let mut encrypted = iv.to_vec();
    encrypted.extend(
        Aes256Gcm::new_from_slice(key)
            .unwrap()
            .encrypt(Nonce::from_slice(&iv), group.as_slice())
            .map_err(|_| anyhow::anyhow!("File-channel proof encryption failed"))?,
    );
    let salt = crate::private::random::<8>()?;
    let mut hash = Sha256::new();
    hash.update(salt);
    hash.update(Sha256::digest(uid.as_bytes()));
    let mut feature = message(1, &salt);
    feature.extend(message(2, &hash.finalize()));
    let mut sync = integer(1, 15000);
    sync.extend(integer(2, 48));
    // The initial client connection uses local key-context index 1.
    sync.extend(integer(3, 1));
    sync.extend(message(4, service.as_bytes()));
    sync.extend(message(5, &feature));
    sync.extend(message(6, &encrypted));
    let mut inner = integer(1, 5);
    inner.extend(message(6, &sync));
    Ok(inner)
}

pub(crate) struct Control<'a> {
    pub kind: u8,
    pub message_id: u16,
    pub body: &'a [u8],
}

pub(crate) struct PortRequest {
    pub channel_type: u32,
    pub client_id: u32,
    pub token: u32,
    pub transfer_key: [u8; 32],
    pub user_key: [u8; 32],
}

/// The encrypted logical request commits to the bulk keys before the plaintext
/// port-control packet arrives. Never trust the latter as a key exchange.
pub(crate) struct PortBinding {
    channel_type: u32,
    client_id: u32,
    transfer_key: [u8; 32],
    user_key: [u8; 32],
}
impl PortBinding {
    pub fn from_user_info(user: &[u8]) -> anyhow::Result<Self> {
        anyhow::ensure!(user.len() <= 4096, "Oversized bulk user info");
        let config = bytes(user, 10)?;
        Ok(Self {
            client_id: u32::try_from(
                number(config, 1).ok_or_else(|| anyhow::anyhow!("Missing bulk client ID"))?,
            )?,
            channel_type: u32::try_from(
                number(user, 1).ok_or_else(|| anyhow::anyhow!("Missing bulk channel type"))?,
            )?,
            transfer_key: bytes(config, 4)?.try_into()?,
            user_key: bytes(config, 5)?.try_into()?,
        })
    }
    pub fn verify(&self, request: &PortRequest) -> anyhow::Result<()> {
        use p256::elliptic_curve::subtle::ConstantTimeEq;
        anyhow::ensure!(
            self.channel_type == request.channel_type && self.client_id == request.client_id,
            "Bulk control identity differs from authenticated request"
        );
        anyhow::ensure!(
            bool::from(
                self.transfer_key.ct_eq(&request.transfer_key)
                    & self.user_key.ct_eq(&request.user_key)
            ),
            "Bulk control keys differ from authenticated request"
        );
        Ok(())
    }
}

pub(crate) fn port_request(control: &Control<'_>) -> anyhow::Result<PortRequest> {
    anyhow::ensure!(control.kind == 2, "Expected peer-port request");
    anyhow::ensure!(control.body.len() <= 512, "Oversized peer-port request");
    let field = |id| -> anyhow::Result<u32> {
        u32::try_from(
            number(control.body, id).ok_or_else(|| anyhow::anyhow!("Missing peer-port integer"))?,
        )
        .map_err(Into::into)
    };
    let client_id = field(1)?;
    anyhow::ensure!(
        (1..=i32::MAX as u32).contains(&client_id),
        "Invalid bulk client ID"
    );
    let channel_type = field(2)?;
    anyhow::ensure!(channel_type == 1, "Unsupported bulk transport type");
    // Native protobuf int32 encodes a negative nonce as a sign-extended
    // ten-byte varint. Preserve its 32-bit bit pattern, rather than rejecting
    // half of the phone's random nonces as an integer overflow.
    let token = number(control.body, 3).ok_or_else(|| anyhow::anyhow!("Missing bulk nonce"))?;
    anyhow::ensure!(
        token <= u32::MAX as u64 || token >= 0xffff_ffff_8000_0000,
        "Invalid bulk nonce width"
    );
    Ok(PortRequest {
        channel_type,
        client_id,
        token: token as u32,
        transfer_key: bytes(control.body, 4)?.try_into()?,
        user_key: bytes(control.body, 5)?.try_into()?,
    })
}

pub(crate) fn control_packet(kind: u8, message_id: u16, body: &[u8]) -> anyhow::Result<Vec<u8>> {
    let size = u16::try_from(16 + body.len())?;
    let mut packet = vec![0x10, 0, kind, 16];
    packet.extend(size.to_be_bytes());
    packet.push(if message_id == 0 { 0 } else { 0x12 });
    packet.extend(message_id.to_be_bytes());
    packet.resize(16, 0);
    packet.extend(body);
    control(&packet)?;
    Ok(packet)
}

pub(crate) fn port_response(
    request: &PortRequest,
    server_id: u32,
    port: u16,
) -> anyhow::Result<Vec<u8>> {
    use crate::wire::integer;
    anyhow::ensure!(server_id != 0 && port != 0, "Invalid bulk listener");
    let mut body = integer(1, request.client_id.into());
    body.extend(integer(2, server_id.into()));
    body.extend(integer(3, port.into()));
    body.extend(integer(5, 1));
    control_packet(3, 0, &body)
}

#[cfg(feature = "file-sharing")]
struct Capture(Option<std::path::PathBuf>);
#[cfg(feature = "file-sharing")]
impl Capture {
    fn enabled(&self) -> bool {
        self.0.is_some()
    }
    fn save(&self, name: impl AsRef<std::path::Path>, bytes: &[u8]) -> anyhow::Result<()> {
        if let Some(directory) = self.0.as_ref() {
            crate::private::save(&directory.join(name), bytes)?;
        }
        Ok(())
    }
}
#[cfg(feature = "file-sharing")]
macro_rules! file_trace {
    ($capture:expr, $($args:tt)*) => {
        if $capture.enabled() || std::env::var_os("MICLIP_DIAGNOSTICS").is_some() {
            println!($($args)*);
        }
    };
}

/// Authenticated file receiver. Raw captures require an explicit research path.
#[cfg(feature = "file-sharing")]
pub(crate) struct FileReceiver {
    listener: std::net::TcpListener,
    datagram: std::net::UdpSocket,
    peer: std::net::IpAddr,
    stream: Option<std::net::TcpStream>,
    capture: Capture,
    started: std::time::Instant,
    last_activity: std::time::Instant,
    done: bool,
    reliable: Option<kcp::Kcp<ProbeOutput>>,
    transfer_key: [u8; 32],
    message_count: u16,
    datagram_count: u8,
    bytes: crate::file_transport::BytesAssembler,
    expected: Option<Vec<(String, Vec<u8>, u64)>>,
    tcp_bytes: Vec<u8>,
    stream_begin_pending: bool,
    receive_directory: Option<std::path::PathBuf>,
    data_key: Option<[u8; 16]>,
    receivers: Vec<(u32, usize, crate::file_stream::Receiver)>,
    saved: Vec<bool>,
    saved_pending: Option<u32>,
    progress_pending: Option<(u64, u64)>,
    completion: Option<Vec<u8>>,
    tcp_pending: Vec<u8>,
    tcp_total: u64,
    clipboard: Option<std::sync::Arc<crate::clipboard_files::Offer>>,
    sends: std::collections::VecDeque<ClipboardSend>,
    sent: u32,
    sent_pending: Option<u32>,
}

#[cfg(feature = "file-sharing")]
struct ClipboardSend {
    index: usize,
    id: u32,
    ready: bool,
    offset: u64,
    ending: bool,
}
#[cfg(feature = "file-sharing")]
struct ProbeOutput(std::net::UdpSocket);
#[cfg(feature = "file-sharing")]
impl std::io::Write for ProbeOutput {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.send(bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
#[cfg(feature = "file-sharing")]
impl FileReceiver {
    pub fn open(
        local: std::net::IpAddr,
        peer: std::net::IpAddr,
        directory: Option<&std::path::Path>,
        transfer_key: [u8; 32],
        receive_directory: Option<&std::path::Path>,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !local.is_unspecified(),
            "Bulk listener requires a specific local interface"
        );
        let listener = std::net::TcpListener::bind((local, 0))?;
        listener.set_nonblocking(true)?;
        // The SDK's event channel negotiates a reliable UDP socket; the later
        // Express data channel has a separate TCP listener. Keep both bound to
        // this research port until the live peer confirms the first framing.
        let datagram = std::net::UdpSocket::bind(listener.local_addr()?)?;
        datagram.set_nonblocking(true)?;
        Ok(Self {
            listener,
            datagram,
            peer,
            stream: None,
            capture: Capture(directory.map(|p| p.to_path_buf())),
            started: std::time::Instant::now(),
            last_activity: std::time::Instant::now(),
            done: false,
            reliable: None,
            transfer_key,
            message_count: 0,
            datagram_count: 0,
            bytes: crate::file_transport::BytesAssembler::default(),
            expected: None,
            tcp_bytes: Vec::new(),
            stream_begin_pending: false,
            receive_directory: receive_directory.map(|p| p.to_path_buf()),
            data_key: None,
            receivers: Vec::new(),
            saved: Vec::new(),
            saved_pending: None,
            progress_pending: None,
            completion: None,
            tcp_pending: Vec::new(),
            tcp_total: 0,
            clipboard: None,
            sends: std::collections::VecDeque::new(),
            sent: 0,
            sent_pending: None,
        })
    }
    pub fn serve_clipboard(&mut self, offer: std::sync::Arc<crate::clipboard_files::Offer>) {
        self.clipboard = Some(offer);
    }
    pub fn take_sent(&mut self) -> Option<u32> {
        self.sent_pending.take()
    }
    fn send_pending(&mut self) -> anyhow::Result<()> {
        let (Some(offer), Some(reliable), Some(send)) = (
            self.clipboard.as_ref(),
            self.reliable.as_mut(),
            // Android may open more than one reader before closing the first.
            // A stream awaiting completion must not block another ready reader.
            self.sends
                .iter_mut()
                .find(|send| send.ready && !send.ending),
        ) else {
            return Ok(());
        };
        if !send.ready || send.ending {
            return Ok(());
        }
        // Bound each poll and the KCP queue so other clipboard events remain
        // responsive. Read directly from the pinned selection in 16 KiB chunks.
        let previous = send.offset;
        for _ in 0..4 {
            if reliable.wait_snd() >= 64 {
                break;
            }
            let bytes = offer.read(send.index, send.offset)?;
            let ending = bytes.is_empty();
            let message = crate::file_transport::sdk_data(
                send.id,
                // Native EOF keeps the final offset; -1 would cancel the stream.
                i64::try_from(send.offset)?,
                &bytes,
            )?;
            reliable.send(&crate::file_transport::seal(&self.transfer_key, &message)?)?;
            send.offset += bytes.len() as u64;
            send.ending = ending;
            self.last_activity = std::time::Instant::now();
            if ending {
                break;
            }
        }
        reliable.flush()?;
        if send.offset != previous || send.ending {
            file_trace!(
                self.capture,
                "Clipboard stream queued: {} bytes; end {}; pending segments {}.",
                send.offset,
                send.ending,
                reliable.wait_snd()
            );
        }
        Ok(())
    }
    pub fn port(&self) -> anyhow::Result<u16> {
        Ok(self.listener.local_addr()?.port())
    }
    pub fn running(&self) -> bool {
        !self.done
    }
    pub fn take_saved(&mut self) -> Option<u32> {
        self.saved_pending.take()
    }
    pub fn take_progress(&mut self) -> Option<(u64, u64)> {
        self.progress_pending.take()
    }
    pub fn completed(&self) -> bool {
        if self.clipboard.is_some() {
            self.sent > 0 && self.sends.is_empty()
        } else {
            !self.saved.is_empty() && self.saved.iter().all(|saved| *saved)
        }
    }
    pub fn trace_peer_close(&self, code: u64) {
        file_trace!(
            self.capture,
            "Phone closed logical file channel: code {code}; streams {}; queued bytes {}; pending segments {}.",
            self.sends.len(),
            self.sends.iter().map(|s| s.offset).sum::<u64>(),
            self.reliable.as_ref().map_or(0, |r| r.wait_snd())
        );
    }
    fn finish(&mut self) -> anyhow::Result<()> {
        self.done = true;
        self.stream.take();
        anyhow::ensure!(
            (self.receive_directory.is_none() && self.sends.is_empty()) || self.completed(),
            "File connection ended before all files were saved"
        );
        Ok(())
    }
    fn receive_pending(&mut self) -> anyhow::Result<()> {
        if self.receive_directory.is_none() || self.tcp_pending.is_empty() {
            return Ok(());
        }
        let key = self
            .data_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("File data arrived before key negotiation"))?;
        let mut consumed = 0;
        while self.tcp_pending.len() - consumed >= 10 {
            let rest = &self.tcp_pending[consumed..];
            let size = crate::file_stream::record_size(rest)?;
            if size > rest.len() {
                break;
            }
            let chunk = crate::file_stream::open(key, &rest[..size])?;
            let receiver = self
                .receivers
                .iter_mut()
                .find(|(id, _, _)| *id == chunk.stream)
                .ok_or_else(|| anyhow::anyhow!("Unrequested file data stream"))?;
            if receiver.2.push(chunk)? {
                self.saved[receiver.1] = true;
                file_trace!(
                    self.capture,
                    "Authenticated file end and manifest length verified; file atomically committed."
                );
            }
            let received = self.receivers.iter().map(|(_, _, r)| r.received()).sum();
            let total = self
                .expected
                .as_ref()
                .unwrap()
                .iter()
                .map(|(_, _, size)| *size)
                .sum();
            self.progress_pending = Some((received, total));
            consumed += size;
        }
        self.tcp_pending.drain(..consumed);
        anyhow::ensure!(
            self.tcp_pending.len() <= crate::file_stream::MAX_RECORD + 10,
            "Oversized pending file data"
        );
        if !self.saved.is_empty() && self.saved.iter().all(|saved| *saved) {
            if let Some(completion) = self.completion.take() {
                self.saved_pending = Some(u32::try_from(self.saved.len())?);
                let message = crate::file_transport::byte_message(0, &completion)?;
                let encrypted = crate::file_transport::seal(&self.transfer_key, &message)?;
                self.capture.save("bulk-send-complete.bin", &encrypted)?;
                let reliable = self.reliable.as_mut().ok_or_else(|| {
                    anyhow::anyhow!("File event transport closed before completion")
                })?;
                reliable.send(&encrypted)?;
                reliable.flush()?;
                file_trace!(
                    self.capture,
                    "All received files committed; encrypted file-complete response sent."
                );
            }
        }
        Ok(())
    }
    pub fn poll(&mut self) -> anyhow::Result<()> {
        let result = self.poll_inner();
        if let Err(error) = &result {
            file_trace!(
                self.capture,
                "File transport stopped: {error}; active streams {}; pending segments {}.",
                self.sends.len(),
                self.reliable.as_ref().map_or(0, |r| r.wait_snd())
            );
        }
        result
    }
    fn poll_inner(&mut self) -> anyhow::Result<()> {
        use std::io::Read;
        if self.done {
            return Ok(());
        }
        if self.last_activity.elapsed().as_secs() >= 60 {
            file_trace!(self.capture, "File transport idle timeout.");
            return self.finish();
        }
        let mut packet = [0; 65536];
        for _ in 0..32 {
            match self.datagram.recv_from(&mut packet) {
                Ok((count, address)) if address.ip() == self.peer => {
                    if self.datagram_count < 64 {
                        self.capture.save(
                            format!("bulk-datagram-{}.bin", self.datagram_count),
                            &packet[..count],
                        )?;
                        self.datagram_count += 1;
                    }
                    crate::file_transport::validate_datagram(&packet[..count])?;
                    if self.reliable.is_none() {
                        self.capture
                            .save("bulk-first-datagram.bin", &packet[..count])?;
                        // Pin the source port as well as the authenticated phone's
                        // address. The KCP conversation constant is only framing.
                        self.datagram.connect(address)?;
                        let output = ProbeOutput(self.datagram.try_clone()?);
                        let mut reliable = kcp::Kcp::new(0x12345678, output);
                        reliable.set_nodelay(true, 20, 2, true);
                        reliable.set_wndsize(32, 128);
                        reliable.set_mtu(1400)?;
                        self.reliable = Some(reliable);
                        file_trace!(
                            self.capture,
                            "Bulk reliable UDP peer connected; no file was received."
                        );
                    }
                    self.reliable.as_mut().unwrap().input(&packet[..count])?;
                }
                Ok(_) => (),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(anyhow::Error::new(e).context("File UDP receive failed")),
            }
        }
        if let Some(reliable) = self.reliable.as_mut() {
            reliable.update(self.started.elapsed().as_millis() as u32)?;
            reliable.flush_ack()?;
            if self.stream_begin_pending && reliable.wait_snd() == 0 {
                self.stream_begin_pending = false;
                file_trace!(
                    self.capture,
                    "File stream receive-begin acknowledged by reliable transport."
                );
            }
            if let Ok(length) = reliable.peeksize() {
                anyhow::ensure!(self.message_count < 512, "Too many bulk control messages");
                anyhow::ensure!(
                    length <= crate::file_transport::MAX_PACKET,
                    "Oversized bulk control"
                );
                let mut message = vec![0; length];
                let count = reliable.recv(&mut message)?;
                anyhow::ensure!(count == length, "Incomplete reliable bulk record");
                let name = if self.message_count == 0 {
                    "bulk-first-message.bin".into()
                } else {
                    format!("bulk-message-{}.bin", self.message_count)
                };
                self.capture.save(name, &message)?;
                self.message_count += 1;
                if let Ok(plaintext) = crate::file_transport::open(&self.transfer_key, &message) {
                    self.last_activity = std::time::Instant::now();
                    let name = if self.message_count == 1 {
                        "bulk-first-plaintext.bin".into()
                    } else {
                        format!("bulk-plaintext-{}.bin", self.message_count)
                    };
                    self.capture.save(name, &plaintext)?;
                    file_trace!(
                        self.capture,
                        "Bulk packet authentication passed; no file was committed."
                    );
                    if let Ok(packet) = crate::file_transport::frame(&plaintext) {
                        if let Some(offer) = self.clipboard.as_ref() {
                            match (packet.kind, packet.tag) {
                                (0x100, 1) => {
                                    let fields = crate::file_transport::nodes(packet.value)?;
                                    anyhow::ensure!(
                                        fields.len() == 1
                                            && fields[0].kind == 5
                                            && fields[0].tag == 0,
                                        "Invalid clipboard byte frame"
                                    );
                                    let reply = offer.reply(fields[0].value)?;
                                    reliable.send(&crate::file_transport::seal(
                                        &self.transfer_key,
                                        &crate::file_transport::sdk_bytes(&reply.message)?,
                                    )?)?;
                                    if let Some(index) = reply.file {
                                        anyhow::ensure!(
                                            self.sends.len() < 128,
                                            "Too many clipboard file requests"
                                        );
                                        let id = (u32::from_ne_bytes(crate::private::random()?)
                                            & 0x3fff_ffff)
                                            + 1;
                                        anyhow::ensure!(
                                            self.sends.iter().all(|s| s.id != id),
                                            "Duplicate stream identity"
                                        );
                                        let source = offer.check(index)?;
                                        reliable.send(&crate::file_transport::seal(
                                            &self.transfer_key,
                                            &crate::file_transport::sdk_stream(
                                                id,
                                                source.size,
                                                &source.name,
                                                source.mime,
                                            )?,
                                        )?)?;
                                        self.sends.push_back(ClipboardSend {
                                            index,
                                            id,
                                            ready: false,
                                            offset: 0,
                                            ending: false,
                                        });
                                        file_trace!(
                                            self.capture,
                                            "Clipboard content response and SDK stream header sent."
                                        );
                                    } else {
                                        file_trace!(
                                            self.capture,
                                            "Clipboard file metadata response sent."
                                        );
                                    }
                                }
                                (0x100, 2) => {
                                    let (id, event) =
                                        crate::file_transport::sdk_event_value(&packet)?;
                                    let send =
                                        self.sends.iter_mut().find(|s| s.id == id).ok_or_else(
                                            || anyhow::anyhow!("Unknown clipboard stream identity"),
                                        )?;
                                    match event {
                                        2 => {
                                            send.ready = true;
                                            file_trace!(
                                                self.capture,
                                                "Clipboard SDK stream accepted by phone."
                                            );
                                        }
                                        3 => {
                                            anyhow::ensure!(
                                                send.ready
                                                    && send.offset == offer.check(send.index)?.size,
                                                "Premature clipboard completion"
                                            );
                                            self.sends.retain(|s| s.id != id);
                                            self.sent += 1;
                                            self.sent_pending = Some(self.sent);
                                            file_trace!(
                                                self.capture,
                                                "Clipboard file completion confirmed by phone."
                                            );
                                        }
                                        _ => {
                                            anyhow::bail!("Phone cancelled clipboard file request")
                                        }
                                    }
                                }
                                _ => anyhow::bail!("Unsupported clipboard SDK frame"),
                            }
                            reliable.flush()?;
                            return Ok(());
                        }
                        if packet.kind == 0x100 && packet.tag == 1 {
                            let fields = crate::file_transport::nodes(packet.value)?;
                            if let Some(data) = fields
                                .iter()
                                .find(|field| field.kind == 5 && field.tag == 0)
                            {
                                self.capture.save(
                                    format!("bulk-express-{}.bin", self.message_count),
                                    data.value,
                                )?;
                                if let Some(complete) = self.bytes.push(data.value)? {
                                    let name = if self.expected.is_none() {
                                        "bulk-file-control.bin".into()
                                    } else {
                                        format!("bulk-file-control-{}.bin", self.message_count)
                                    };
                                    self.capture.save(name, &complete)?;
                                    file_trace!(
                                        self.capture,
                                        "Complete file-share control message reassembled and saved privately. No file body was committed."
                                    );
                                    if self.expected.is_none() {
                                        let manifest = crate::file_protocol::request(&complete)?;
                                        self.saved = vec![false; manifest.files.len()];
                                        self.completion =
                                            Some(crate::file_protocol::completion(&manifest));
                                        self.expected = Some(
                                            manifest
                                                .files
                                                .iter()
                                                .map(|f| (f.name.into(), f.id.to_vec(), f.size))
                                                .collect(),
                                        );
                                        let response = crate::file_protocol::accept(&manifest);
                                        let message =
                                            crate::file_transport::byte_message(0, &response)?;
                                        let encrypted = crate::file_transport::seal(
                                            &self.transfer_key,
                                            &message,
                                        )?;
                                        self.capture.save("bulk-send-accept.bin", &encrypted)?;
                                        reliable.send(&encrypted)?;
                                        reliable.flush()?;
                                        file_trace!(
                                            self.capture,
                                            "Validated file-share manifest; encrypted request acceptance sent for data-channel inspection. No file was committed."
                                        );
                                    }
                                }
                                if let Some(offer) =
                                    crate::file_transport::stream_offer(data.value)?
                                {
                                    let (index, size) = self
                                        .expected
                                        .as_ref()
                                        .and_then(|files| {
                                            files.iter().enumerate().find_map(
                                                |(i, (name, id, size))| {
                                                    (name == offer.name
                                                        && id.as_slice() == offer.tag
                                                        && offer
                                                            .length
                                                            .is_none_or(|length| *size == length))
                                                    .then_some((i, *size))
                                                },
                                            )
                                        })
                                        .ok_or_else(|| {
                                            anyhow::anyhow!(
                                                "Stream differs from accepted file manifest"
                                            )
                                        })?;
                                    if let Some(directory) = self.receive_directory.as_ref() {
                                        anyhow::ensure!(
                                            !self.saved[index],
                                            "File already received in this transfer"
                                        );
                                        if !self
                                            .receivers
                                            .iter()
                                            .any(|(id, i, _)| *id == offer.id && *i == index)
                                        {
                                            anyhow::ensure!(
                                                self.receivers.iter().all(|(id, i, _)| *id
                                                    != offer.id
                                                    && *i != index),
                                                "Conflicting file stream identity"
                                            );
                                            self.receivers.push((
                                                offer.id,
                                                index,
                                                crate::file_stream::Receiver::new(
                                                    offer.id, directory, offer.name, size,
                                                )?,
                                            ));
                                        }
                                    }
                                    let received =
                                        self.receivers.iter().map(|(_, _, r)| r.received()).sum();
                                    let total = self
                                        .expected
                                        .as_ref()
                                        .unwrap()
                                        .iter()
                                        .map(|(_, _, size)| *size)
                                        .sum();
                                    self.progress_pending = Some((received, total));
                                    let message = crate::file_transport::stream_begin(offer.id)?;
                                    let encrypted =
                                        crate::file_transport::seal(&self.transfer_key, &message)?;
                                    self.capture
                                        .save("bulk-send-stream-begin.bin", &encrypted)?;
                                    reliable.send(&encrypted)?;
                                    reliable.flush()?;
                                    self.stream_begin_pending = true;
                                    file_trace!(
                                        self.capture,
                                        "Authenticated file stream matched accepted manifest; receive-begin sent. No file was committed."
                                    );
                                }
                            }
                        }
                        // Keep acknowledging event traffic while the separate
                        // TCP socket is opening; capturing one control record
                        // is not transfer completion.
                        return Ok(());
                    }
                } else if let Ok(Some(response)) =
                    crate::file_transport::negotiation_reply(&message, 1)
                {
                    let info = crate::file_transport::frame(&message)?;
                    let fields = crate::file_transport::nodes(info.value)?;
                    if let Some(maximum) = fields.iter().find(|field| field.tag == 2) {
                        file_trace!(
                            self.capture,
                            "Phone SDK packet limit: {}.",
                            u32::from_be_bytes(maximum.value.try_into()?)
                        );
                    }
                    reliable.send(&response)?;
                    if self.clipboard.is_some() {
                        reliable.flush()?;
                        file_trace!(self.capture, "Clipboard SDK event framing negotiated.");
                        return Ok(());
                    }
                    let challenge = crate::private::random::<16>()?;
                    self.data_key = Some(challenge);
                    self.capture.save("bulk-challenge.bin", &challenge)?;
                    let offer = crate::file_transport::data_socket_offer(
                        self.listener.local_addr()?.port(),
                        &challenge,
                    )?;
                    reliable.send(&crate::file_transport::seal(&self.transfer_key, &offer)?)?;
                    reliable.flush()?;
                    file_trace!(
                        self.capture,
                        "Bulk event framing negotiated; encrypted TCP socket offer sent. No file was committed."
                    );
                    return Ok(());
                } else if crate::file_transport::frame(&message).is_ok() {
                    file_trace!(
                        self.capture,
                        "Bulk negotiation TLV captured privately; no file was committed."
                    );
                } else {
                    file_trace!(
                        self.capture,
                        "Bulk control captured privately; framing needs validation."
                    );
                }
                return self.finish();
            }
        }
        if self.stream.is_none() {
            match self.listener.accept() {
                Ok((stream, address)) if address.ip() == self.peer => {
                    stream.set_nonblocking(true)?;
                    self.stream = Some(stream);
                    file_trace!(
                        self.capture,
                        "Bulk TCP peer connected; transfer framing still requires validation."
                    );
                }
                Ok(_) => (),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => (),
                Err(e) => return Err(anyhow::Error::new(e).context("File TCP accept failed")),
            }
        }
        if let Some(stream) = self.stream.as_mut() {
            let mut bytes = [0; 65536];
            match stream.read(&mut bytes) {
                Ok(0) => {
                    file_trace!(self.capture, "File TCP stream closed.");
                    return self.finish();
                }
                Ok(count) => {
                    self.last_activity = std::time::Instant::now();
                    if self.tcp_total == 0 {
                        self.capture.save("bulk-first-frame.bin", &bytes[..count])?;
                        file_trace!(
                            self.capture,
                            "Bulk TCP transport bytes captured privately; no file was committed."
                        );
                    }
                    self.tcp_total += count as u64;
                    if self.capture.enabled() && self.tcp_bytes.len() < 4 * 1024 * 1024 {
                        let capture = count.min(4 * 1024 * 1024 - self.tcp_bytes.len());
                        self.tcp_bytes.extend(&bytes[..capture]);
                        self.capture.save("bulk-tcp-stream.bin", &self.tcp_bytes)?;
                    }
                    if self.receive_directory.is_some() {
                        self.tcp_pending.extend(&bytes[..count]);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => (),
                Err(e) => return Err(anyhow::Error::new(e).context("File TCP read failed")),
            }
        }
        self.receive_pending()?;
        self.send_pending()?;
        Ok(())
    }
}

/// The control channel has its own 16-byte header inside the encrypted envelope.
pub(crate) fn control(packet: &[u8]) -> anyhow::Result<Control<'_>> {
    anyhow::ensure!(
        (16..=u16::MAX as usize).contains(&packet.len()),
        "Invalid channel control length"
    );
    anyhow::ensure!(
        packet[0] == 0x10 && packet[1] == 0 && packet[3] == 16,
        "Unsupported channel control header"
    );
    anyhow::ensure!(
        u16::from_be_bytes([packet[4], packet[5]]) as usize == packet.len(),
        "Channel control length mismatch"
    );
    anyhow::ensure!(
        (1..=7).contains(&packet[2]),
        "Unsupported channel control type"
    );
    anyhow::ensure!(
        matches!(packet[6], 0 | 0x12) && packet[9..16].iter().all(|&b| b == 0),
        "Unsupported channel control options"
    );
    let message_id = u16::from_be_bytes([packet[7], packet[8]]);
    anyhow::ensure!(
        (packet[6] == 0) == (message_id == 0),
        "Invalid channel control message ID"
    );
    Ok(Control {
        kind: packet[2],
        message_id,
        body: &packet[16..],
    })
}

/// Reuse only the key and certificate established by the current live handshake.
pub(crate) fn incoming(
    logical: &[u8],
    key: &[u8; 32],
    peer: &VerifyingKey,
) -> anyhow::Result<Option<Incoming>> {
    incoming_to(logical, key, peer, 0)
}

pub(crate) fn incoming_to(
    logical: &[u8],
    key: &[u8; 32],
    peer: &VerifyingKey,
    destination: u8,
) -> anyhow::Result<Option<Incoming>> {
    if number(logical, 4).unwrap_or(0) != 0 {
        return Ok(None);
    }
    let Ok(inner) = bytes(logical, 5) else {
        return Ok(None);
    };
    if number(inner, 1) != Some(5) {
        return Ok(None);
    }
    let sync = bytes(inner, 6)?;
    let sync_fields =
        wire::fields(sync).ok_or_else(|| anyhow::anyhow!("Malformed file-channel sync info"))?;
    let mut service_fields = sync_fields
        .iter()
        .filter(|field| matches!(field, Field::Integer(4, _) | Field::Bytes(4, _)));
    let service_name = match service_fields.next() {
        Some(Field::Bytes(_, value)) => Some(*value),
        None => None,
        _ => anyhow::bail!("Invalid file-channel service name"),
    };
    anyhow::ensure!(
        service_fields.next().is_none(),
        "Duplicate file-channel service name"
    );
    // A server's sync response need not echo the requested service name. The
    // initiator has already selected it; still require the current channel's
    // nonce, destination, encrypted credential and enrolled peer signature.
    let service = match service_name {
        None | Some(b"") if destination == 2 => PHONE_SHARE_SERVICE,
        Some(b"com.xiaomi.hyperConnect:miLyraShareTransfer") => SHARE_SERVICE,
        Some(b"com.miui.mishare.connectivity:miLyraShareTransfer") if destination != 0 => {
            PHONE_SHARE_SERVICE
        }
        Some(b"com.xiaomi.hyperConnect:universalClipboard") => {
            "com.xiaomi.hyperConnect:universalClipboard"
        }
        Some(b"com.milink.service:universalClipboard") => "com.milink.service:universalClipboard",
        _ => return Ok(None),
    };
    anyhow::ensure!(logical.len() <= 4096, "Oversized file-channel request");
    anyhow::ensure!(
        number(logical, 2).unwrap_or(0) == u64::from(destination),
        "Unexpected file-channel destination"
    );
    let peer_id = u8::try_from(number(logical, 1).unwrap_or(0))?;
    anyhow::ensure!(peer_id > 1, "Invalid file-channel source");
    let nonce =
        u32::try_from(number(logical, 3).ok_or_else(|| anyhow::anyhow!("Missing channel nonce"))?)?;
    let encrypted = bytes(sync, 6)?;
    anyhow::ensure!(
        (28..=2048).contains(&encrypted.len()),
        "Invalid file-channel credential size"
    );
    let clear = Aes256Gcm::new_from_slice(key)
        .unwrap()
        .decrypt(Nonce::from_slice(&encrypted[..12]), &encrypted[12..])
        .map_err(|_| anyhow::anyhow!("File-channel credential authentication failed"))?;
    anyhow::ensure!(
        number(&clear, 1) == Some(1),
        "Unsupported file-channel credential group"
    );
    let credential = bytes(&clear, 3)?;
    anyhow::ensure!(
        number(credential, 1) == Some(2),
        "Unsupported file-channel credential type"
    );
    let proof = bytes(credential, 3)?;
    let challenge = bytes(proof, 1)?;
    anyhow::ensure!(challenge.len() == 32, "Invalid file-channel challenge");
    peer.verify(challenge, &Signature::from_der(bytes(proof, 2)?)?)
        .map_err(|_| anyhow::anyhow!("File-channel peer signature failed"))?;
    Ok(Some(Incoming {
        peer_id,
        nonce,
        service,
    }))
}

pub(crate) fn incoming_share_response(
    logical: &[u8],
    key: &[u8; 32],
    peer: &VerifyingKey,
    nonce: u32,
) -> anyhow::Result<Option<Incoming>> {
    if number(logical, 2) != Some(2) || number(logical, 3) != Some(u64::from(nonce)) {
        return Ok(None);
    }
    let inner = bytes(logical, 5)?;
    if number(inner, 1) != Some(5) {
        return Ok(None);
    }
    if std::env::var_os("MICLIP_DIAGNOSTICS").is_some() {
        let fields = wire::fields(bytes(inner, 6)?)
            .ok_or_else(|| anyhow::anyhow!("Malformed share sync response"))?;
        let schema: Vec<_> = fields
            .iter()
            .map(|f| match f {
                Field::Bytes(id, _) => format!("{id}:bytes"),
                Field::Integer(id, _) => format!("{id}:integer"),
            })
            .collect();
        eprintln!("Mi Clip Share: sync response fields {}", schema.join(", "));
    }
    let response = incoming_to(logical, key, peer, 2)?;
    anyhow::ensure!(
        response
            .as_ref()
            .is_some_and(|r| r.service == PHONE_SHARE_SERVICE),
        "Unexpected share response service"
    );
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "file-sharing")]
    #[test]
    fn clipboard_pull_uses_direct_sdk_frames_and_waits_for_phone_completion() {
        for completion_at_size in [false, true] {
            for image in [false, true] {
                clipboard_pull(completion_at_size, image, 1);
            }
        }
    }
    #[cfg(feature = "file-sharing")]
    #[test]
    fn concurrent_image_readers_do_not_wait_for_the_first_reader_to_close() {
        clipboard_pull(false, true, 2);
    }
    #[cfg(feature = "file-sharing")]
    fn clipboard_pull(completion_at_size: bool, image: bool, readers: u32) {
        use crate::file_transport as ft;
        use std::{
            net::{IpAddr, Ipv4Addr, UdpSocket},
            sync::Arc,
            time::{Duration, Instant},
        };
        let root = std::env::temp_dir().join(format!(
            "clip-pull-{:016x}",
            u64::from_ne_bytes(crate::private::random().unwrap())
        ));
        std::fs::create_dir(&root).unwrap();
        let content: Vec<_> = (0..700_000).map(|n| (n % 251) as u8).collect();
        let path = root.join("synthetic.bin");
        std::fs::write(&path, &content).unwrap();
        let local = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let key = [0x42; 32];
        let mut server = FileReceiver::open(local, local, None, key, None).unwrap();
        let offer = if image {
            crate::clipboard_files::Offer::from_content(
                crate::clipboard::Content::Image(crate::clipboard::Image {
                    name: "Clipboard.png",
                    bytes: content.clone(),
                }),
                7,
            )
            .unwrap()
        } else {
            crate::clipboard_files::Offer::open(vec![path], 7).unwrap()
        };
        server.serve_clipboard(Arc::new(offer));
        let socket = UdpSocket::bind((local, 0)).unwrap();
        socket.connect((local, server.port().unwrap())).unwrap();
        socket.set_nonblocking(true).unwrap();
        let mut peer = kcp::Kcp::new(0x12345678, ProbeOutput(socket.try_clone().unwrap()));
        peer.set_nodelay(true, 20, 2, true);
        peer.set_wndsize(32, 128);
        peer.set_mtu(1400).unwrap();
        let mut info = ft::tlv(3, 0, &1u32.to_be_bytes()).unwrap();
        info.extend(ft::tlv(3, 1, &1u32.to_be_bytes()).unwrap());
        info.extend(ft::tlv(3, 2, &0xff00u32.to_be_bytes()).unwrap());
        let mut branch = 0u16.to_be_bytes().to_vec();
        branch.extend(ft::tlv(256, 0, &info).unwrap());
        peer.send(&ft::tlv(257, u16::MAX, &branch).unwrap())
            .unwrap();
        peer.update(0).unwrap();
        let started = Instant::now();
        let mut packet = [0; 65536];
        let mut streams = std::collections::BTreeMap::<u32, (Vec<u8>, bool)>::new();
        let mut acknowledged = false;
        let mut metadata = false;
        while started.elapsed() < Duration::from_secs(5) && server.sent < readers {
            server.poll().unwrap();
            peer.update(started.elapsed().as_millis() as u32).unwrap();
            loop {
                match socket.recv(&mut packet) {
                    Ok(n) => {
                        peer.input(&packet[..n]).unwrap();
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) => panic!("{e}"),
                }
            }
            while let Ok(size) = peer.peeksize() {
                let mut message = vec![0; size];
                peer.recv(&mut message).unwrap();
                let Ok(plain) = ft::open(&key, &message) else {
                    assert_eq!(ft::frame(&message).unwrap().tag, 4);
                    // Shape of the real phone's first request: direct protobuf.
                    let request = [8, 1, 26, 2, 8, 7];
                    peer.send(&ft::seal(&key, &ft::sdk_bytes(&request).unwrap()).unwrap())
                        .unwrap();
                    continue;
                };
                let sdk = ft::frame(&plain).unwrap();
                let fields = ft::nodes(sdk.value).unwrap();
                match sdk.tag {
                    1 => {
                        let reply = fields[0].value;
                        match number(reply, 1) {
                            Some(3) => {
                                assert!(crate::wire::bytes_field(reply, 5).is_some());
                                metadata = true;
                                let request = [8, 4, 50, 2, 8, 7];
                                for _ in 0..readers {
                                    peer.send(
                                        &ft::seal(&key, &ft::sdk_bytes(&request).unwrap()).unwrap(),
                                    )
                                    .unwrap();
                                }
                            }
                            Some(5) => assert!(crate::wire::bytes_field(reply, 7).is_some()),
                            _ => panic!("Unexpected clipboard reply"),
                        }
                    }
                    2 => {
                        assert!(metadata);
                        let id = u32::from_be_bytes(fields[0].value.try_into().unwrap());
                        assert_eq!(u32::from_be_bytes(fields[1].value.try_into().unwrap()), 1);
                        assert!(streams.insert(id, (Vec::new(), false)).is_none());
                        let header = ft::nodes(&fields[2].value[2..]).unwrap();
                        let attrs = ft::nodes(header[0].value).unwrap();
                        assert_eq!(
                            u64::from_be_bytes(attrs[0].value.try_into().unwrap()),
                            content.len() as u64
                        );
                        peer.send(&ft::seal(&key, &ft::sdk_event(id, 2).unwrap()).unwrap())
                            .unwrap();
                    }
                    3 => {
                        let id = u32::from_be_bytes(fields[0].value.try_into().unwrap());
                        let (received, ended) =
                            streams.get_mut(&id).expect("Data before stream header");
                        let offset = i64::from_be_bytes(fields[1].value.try_into().unwrap());
                        let count =
                            u32::from_be_bytes(fields[2].value.try_into().unwrap()) as usize;
                        assert_eq!(count, fields[3].value.len());
                        if *ended {
                            continue;
                        }
                        assert_eq!(server.sent, 0, "Completion must wait for the phone");
                        if count == 0 {
                            assert_eq!(offset, content.len() as i64);
                            *ended = true;
                        } else {
                            assert_eq!(offset as usize, received.len());
                            received.extend(fields[3].value);
                            if completion_at_size && received.len() == content.len() {
                                *ended = true;
                            }
                        }
                        // Model Android opening two readers and withholding close
                        // acknowledgements until both have received their bytes.
                        if !acknowledged
                            && streams.len() == readers as usize
                            && streams.values().all(|(_, ended)| *ended)
                        {
                            for id in streams.keys() {
                                peer.send(
                                    &ft::seal(&key, &ft::sdk_event(*id, 3).unwrap()).unwrap(),
                                )
                                .unwrap();
                            }
                            acknowledged = true;
                        }
                    }
                    _ => panic!("Unexpected SDK frame"),
                }
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(streams.len(), readers as usize);
        for (received, ended) in streams.values() {
            assert!(
                *ended,
                "A reader stalled waiting for another reader to close"
            );
            assert_eq!(*received, content);
        }
        assert_eq!(server.take_sent(), Some(readers));
        assert!(server.completed());
        drop(server);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[cfg(feature = "file-sharing")]
    #[test]
    fn resident_receiver_does_not_capture_packets() {
        let target = std::env::temp_dir().join(format!(
            "clip-no-capture-{:016x}",
            u64::from_ne_bytes(crate::private::random().unwrap())
        ));
        let capture = Capture(None);
        assert!(!capture.enabled());
        capture.save(&target, b"synthetic private data").unwrap();
        assert!(!target.exists());
    }
    #[cfg(feature = "file-sharing")]
    #[test]
    fn private_probe_receives_reliable_encrypted_control_over_loopback() {
        use std::{
            fs,
            net::UdpSocket,
            time::{Duration, Instant},
        };
        let root = std::env::temp_dir().join(format!(
            "clip-bulk-probe-{:016x}",
            u64::from_ne_bytes(crate::private::random().unwrap())
        ));
        fs::create_dir(&root).unwrap();
        let key = [0x42; 32];
        let local = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let mut probe = FileReceiver::open(local, local, Some(&root), key, None).unwrap();
        let socket = UdpSocket::bind((local, 0)).unwrap();
        socket.connect((local, probe.port().unwrap())).unwrap();
        let mut peer = kcp::Kcp::new(0x12345678, ProbeOutput(socket));
        peer.set_nodelay(true, 20, 2, true);
        let encrypted = crate::file_transport::seal(&key, b"synthetic control").unwrap();
        peer.send(&encrypted).unwrap();
        peer.update(0).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while !probe.done && Instant::now() < deadline {
            probe.poll().unwrap();
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(probe.done);
        assert_eq!(
            fs::read(root.join("bulk-first-message.bin")).unwrap(),
            encrypted
        );
        assert_eq!(
            fs::read(root.join("bulk-first-plaintext.bin")).unwrap(),
            b"synthetic control"
        );
        drop(probe);
        fs::remove_dir_all(root).unwrap();
    }
    use crate::wire::{integer, message};
    use p256::ecdsa::{SigningKey, signature::Signer};
    #[test]
    fn peer_channel_ids_can_change_without_changing_transport() {
        for id in [1, 136, 145, 32768, i32::MAX as u64] {
            let mut body = integer(1, id);
            body.extend(integer(2, 1));
            body.extend(integer(3, 123));
            body.extend(message(4, &[1; 32]));
            body.extend(message(5, &[2; 32]));
            let packet = control_packet(2, 0, &body).unwrap();
            let request = port_request(&control(&packet).unwrap()).unwrap();
            assert_eq!(request.client_id as u64, id);
            assert_eq!(request.channel_type, 1);
            let response = port_response(&request, 7, 12345).unwrap();
            assert_eq!(number(control(&response).unwrap().body, 1), Some(id));
        }
        for token in [0, u32::MAX as u64, 0xffff_ffff_8000_0000, u64::MAX] {
            let mut body = integer(1, 145);
            body.extend(integer(2, 1));
            body.extend(integer(3, token));
            body.extend(message(4, &[1; 32]));
            body.extend(message(5, &[2; 32]));
            let packet = control_packet(2, 0, &body).unwrap();
            assert_eq!(
                port_request(&control(&packet).unwrap()).unwrap().token,
                token as u32
            );
        }
        for (id, kind) in [(0, 1), (u32::MAX as u64, 1), (145, 2)] {
            let mut body = integer(1, id);
            body.extend(integer(2, kind));
            body.extend(integer(3, 123));
            body.extend(message(4, &[1; 32]));
            body.extend(message(5, &[2; 32]));
            let packet = control_packet(2, 0, &body).unwrap();
            assert!(port_request(&control(&packet).unwrap()).is_err());
        }
    }
    #[test]
    fn port_control_cannot_replace_authenticated_keys_or_open_an_unsupported_transport() {
        let mut commitment = integer(1, 136);
        commitment.extend(message(4, &[1; 32]));
        commitment.extend(message(5, &[2; 32]));
        let mut user = integer(1, 1);
        user.extend(message(10, &commitment));
        let binding = PortBinding::from_user_info(&user).unwrap();
        let mut body = integer(1, 136);
        body.extend(integer(2, 1));
        body.extend(integer(3, 123));
        body.extend(message(4, &[1; 32]));
        body.extend(message(5, &[2; 32]));
        let packet = control_packet(2, 0, &body).unwrap();
        let mut request = port_request(&control(&packet).unwrap()).unwrap();
        assert_eq!(request.token, 123);
        binding.verify(&request).unwrap();
        request.transfer_key[0] ^= 1;
        assert!(binding.verify(&request).is_err());
        request.transfer_key[0] ^= 1;
        request.client_id += 1;
        assert!(binding.verify(&request).is_err());
        let response = port_response(&request, 9, 12345).unwrap();
        let response = control(&response).unwrap();
        assert_eq!(
            (
                response.kind,
                number(response.body, 2),
                number(response.body, 3)
            ),
            (3, Some(9), Some(12345))
        );
        assert!(port_request(&response).is_err());
        assert!(port_response(&request, 0, 12345).is_err());
        for end in 0..body.len() {
            if let Ok(packet) = control_packet(2, 0, &body[..end]) {
                assert!(port_request(&control(&packet).unwrap()).is_err());
            }
        }
    }
    #[test]
    fn control_header_rejects_truncation_length_mismatch_and_unknown_options() {
        let mut packet = vec![0x10, 0, 1, 16, 0, 18, 0x12, 1, 2, 0, 0, 0, 0, 0, 0, 0, 8, 1];
        let frame = control(&packet).unwrap();
        assert_eq!(
            (frame.kind, frame.message_id, frame.body),
            (1, 258, &[8, 1][..])
        );
        for end in 0..packet.len() {
            assert!(control(&packet[..end]).is_err())
        }
        packet[6] = 0;
        assert!(control(&packet).is_err());
        packet[7..9].fill(0);
        assert!(control(&packet).is_ok());
        packet[9] = 1;
        assert!(control(&packet).is_err());
    }
    #[test]
    fn accepts_current_peer_and_rejects_wrong_key_signature_and_tampering() {
        let signing = SigningKey::from_slice(&[1; 32]).unwrap();
        let challenge = [9; 32];
        let signature: Signature = signing.sign(&challenge);
        let mut proof = message(1, &challenge);
        proof.extend(message(2, signature.to_der().as_bytes()));
        let mut credential = integer(1, 2);
        credential.extend(message(3, &proof));
        let mut group = integer(1, 1);
        group.extend(message(3, &credential));
        let key = [3; 32];
        let reply = sync_reply(&key, &signing, "1234").unwrap();
        let mut reply_logical = integer(1, 2);
        reply_logical.extend(integer(3, 123));
        reply_logical.extend(message(5, &reply));
        assert!(
            incoming(&reply_logical, &key, signing.verifying_key())
                .unwrap()
                .is_some()
        );
        let iv = [4; 12];
        let mut encrypted = iv.to_vec();
        encrypted.extend(
            Aes256Gcm::new_from_slice(&key)
                .unwrap()
                .encrypt(Nonce::from_slice(&iv), group.as_slice())
                .unwrap(),
        );
        let mut sync = message(4, b"com.xiaomi.hyperConnect:miLyraShareTransfer");
        sync.extend(message(6, &encrypted));
        let mut inner = integer(1, 5);
        inner.extend(message(6, &sync));
        let mut logical = integer(1, 2);
        logical.extend(integer(3, 123));
        logical.extend(message(5, &inner));
        let request = incoming(&logical, &key, signing.verifying_key())
            .unwrap()
            .unwrap();
        assert_eq!((request.peer_id, request.nonce), (2, 123));
        assert!(incoming(&logical, &[5; 32], signing.verifying_key()).is_err());
        let wrong = SigningKey::from_slice(&[2; 32]).unwrap();
        assert!(incoming(&logical, &key, wrong.verifying_key()).is_err());
        let end = logical.len() - 1;
        logical[end] ^= 1;
        assert!(incoming(&logical, &key, signing.verifying_key()).is_err());
    }
}

#[cfg(test)]
mod share_recipient_tests {
    use super::*;
    fn server_reply(
        key: &[u8; 32],
        signing: &SigningKey,
        service: Option<&[u8]>,
        credential: bool,
    ) -> Vec<u8> {
        let original =
            sync_reply_for_service(key, signing, "synthetic", PHONE_SHARE_SERVICE).unwrap();
        let mut sync = Vec::new();
        for field in wire::fields(bytes(&original, 6).unwrap()).unwrap() {
            match field {
                Field::Bytes(4, _) => (),
                Field::Bytes(6, _) if !credential => (),
                Field::Bytes(id, value) => sync.extend(wire::message(id, value)),
                Field::Integer(id, value) => sync.extend(wire::integer(id, value)),
            }
        }
        if let Some(service) = service {
            sync.extend(wire::message(4, service));
        }
        let mut inner = wire::integer(1, 5);
        inner.extend(wire::message(6, &sync));
        let mut logical = wire::integer(1, 3);
        logical.extend(wire::integer(2, 2));
        logical.extend(wire::integer(3, 123));
        logical.extend(wire::message(5, &inner));
        logical
    }
    #[test]
    fn server_may_omit_the_echo_but_not_the_authenticated_credential() {
        let signing = SigningKey::from_slice(&[1; 32]).unwrap();
        let other = SigningKey::from_slice(&[2; 32]).unwrap();
        let key = [3; 32];
        for service in [
            None,
            Some(b"".as_slice()),
            Some(PHONE_SHARE_SERVICE.as_bytes()),
        ] {
            let reply = server_reply(&key, &signing, service, true);
            let response = incoming_share_response(&reply, &key, signing.verifying_key(), 123)
                .unwrap()
                .unwrap();
            assert_eq!(response.service, PHONE_SHARE_SERVICE);
            assert!(
                incoming_share_response(&reply, &key, signing.verifying_key(), 124)
                    .unwrap()
                    .is_none()
            );
            assert!(
                incoming_share_response(&reply, &[4; 32], signing.verifying_key(), 123).is_err()
            );
            assert!(incoming_share_response(&reply, &key, other.verifying_key(), 123).is_err());
            let mut tampered = reply;
            *tampered.last_mut().unwrap() ^= 1;
            assert!(
                incoming_share_response(&tampered, &key, signing.verifying_key(), 123).is_err()
            );
        }
        let missing_proof = server_reply(&key, &signing, None, false);
        assert!(
            incoming_share_response(&missing_proof, &key, signing.verifying_key(), 123).is_err()
        );
        let wrong_service = server_reply(&key, &signing, Some(SHARE_SERVICE.as_bytes()), true);
        assert!(
            incoming_share_response(&wrong_service, &key, signing.verifying_key(), 123).is_err()
        );
    }
    #[test]
    fn outgoing_service_matches_the_phone_advertisement_and_keeps_mac_receiver_distinct() {
        let signing = SigningKey::from_slice(&[1; 32]).unwrap();
        let key = [3; 32];
        let frame =
            sync_reply_for_service(&key, &signing, "synthetic", PHONE_SHARE_SERVICE).unwrap();
        let sync = bytes(&frame, 6).unwrap();
        assert_eq!(
            bytes(sync, 4).unwrap(),
            format!(
                "{}:{}",
                crate::networking::PHONE_PACKAGE,
                crate::networking::FILE_TRANSFER
            )
            .as_bytes()
        );
        assert_ne!(PHONE_SHARE_SERVICE, SHARE_SERVICE);
        let mut logical = crate::wire::integer(1, 3);
        logical.extend(crate::wire::integer(2, 2));
        logical.extend(crate::wire::integer(3, 123));
        logical.extend(crate::wire::message(5, &frame));
        assert!(
            incoming_to(&logical, &key, signing.verifying_key(), 2)
                .unwrap()
                .is_some()
        );
        assert!(
            incoming(&logical, &key, signing.verifying_key())
                .unwrap()
                .is_none()
        );
    }
}
