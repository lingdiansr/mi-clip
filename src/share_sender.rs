//! Initiating side of native HyperConnect file sharing. Clipboard offers are
//! deliberately not involved: the receiver accepts and saves a share task.
use crate::{
    file_transport as ft,
    wire::{self, Field},
};
use std::{
    io::Write,
    net::{SocketAddr, TcpStream, UdpSocket},
    time::{Duration, Instant},
};

struct Output(UdpSocket);
impl Write for Output {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.0.send(data)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn number(input: &[u8], id: u32) -> anyhow::Result<u64> {
    let fields = wire::fields(input).ok_or_else(|| anyhow::anyhow!("Malformed share response"))?;
    let mut values = fields
        .iter()
        .filter(|f| matches!(f, Field::Integer(n, _) | Field::Bytes(n, _) if *n == id));
    let value = match values.next() {
        Some(Field::Integer(_, v)) => *v,
        None => 0,
        _ => anyhow::bail!("Invalid share integer"),
    };
    anyhow::ensure!(values.next().is_none(), "Duplicate share integer");
    Ok(value)
}
fn bytes(input: &[u8], id: u32) -> anyhow::Result<&[u8]> {
    wire::bytes_field(input, id).ok_or_else(|| anyhow::anyhow!("Missing share response field"))
}
fn node<'a>(nodes: &[ft::Node<'a>], tag: u16, kind: u16) -> anyhow::Result<&'a [u8]> {
    let mut values = nodes.iter().filter(|n| n.tag == tag);
    let n = values
        .next()
        .ok_or_else(|| anyhow::anyhow!("Missing share transport field"))?;
    anyhow::ensure!(
        n.kind == kind && values.next().is_none(),
        "Invalid share transport field"
    );
    Ok(n.value)
}

pub(crate) struct Sender {
    pub request: crate::share_queue::Request,
    pub nonce: u32,
    pub key: [u8; 32],
    user_key: [u8; 32],
    client_id: u32,
    pub peer: Option<u8>,
    started: Instant,
    activity: Instant,
    reliable: Option<kcp::Kcp<Output>>,
    socket: Option<UdpSocket>,
    address: Option<SocketAddr>,
    stream: Option<TcpStream>,
    data_key: Option<[u8; 16]>,
    task: String,
    accepted: bool,
    announced: bool,
    streams: Vec<(u32, usize, u64, bool, bool)>,
    pending: Vec<u8>,
    pending_offset: usize,
    assembler: ft::BytesAssembler,
    complete: bool,
}
impl Sender {
    pub fn new(request: crate::share_queue::Request) -> anyhow::Result<Self> {
        let now = Instant::now();
        crate::share_queue::validate_selected(request.target)?;
        Ok(Self {
            request,
            nonce: u32::from_ne_bytes(crate::private::random()?) & 0x7fff_ffff,
            key: crate::private::random()?,
            user_key: crate::private::random()?,
            client_id: 1,
            peer: None,
            started: now,
            activity: now,
            reliable: None,
            socket: None,
            address: None,
            stream: None,
            data_key: None,
            task: format!("{:016x}", u64::from_ne_bytes(crate::private::random()?)),
            accepted: false,
            announced: false,
            streams: Vec::new(),
            pending: Vec::new(),
            pending_offset: 0,
            assembler: ft::BytesAssembler::default(),
            complete: false,
        })
    }
    pub fn logical_request(&self) -> Vec<u8> {
        let mut config = wire::integer(1, self.client_id.into());
        config.extend(wire::message(4, &self.key));
        config.extend(wire::message(5, &self.user_key));
        let mut user = wire::integer(1, 1);
        user.extend(wire::message(2, b"com.cyeam.miclip"));
        user.extend(wire::message(10, &config));
        let mut body = wire::message(2, crate::file_channel::PHONE_SHARE_SERVICE.as_bytes());
        body.extend(wire::message(3, &user));
        body.extend(wire::integer(4, 16));
        body.extend(wire::integer(5, 10000));
        body.extend(wire::integer(6, 256));
        body.extend(wire::integer(7, 1));
        let mut out = wire::integer(1, 1);
        out.extend(wire::message(2, &body));
        out
    }
    pub fn port_request(&self) -> anyhow::Result<Vec<u8>> {
        let mut body = wire::integer(1, self.client_id.into());
        body.extend(wire::integer(2, 1));
        body.extend(wire::integer(3, self.nonce.into()));
        body.extend(wire::message(4, &self.key));
        body.extend(wire::message(5, &self.user_key));
        crate::file_channel::control_packet(2, 0, &body)
    }
    pub fn connect(
        &mut self,
        control: &crate::file_channel::Control<'_>,
        peer: SocketAddr,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.reliable.is_none() && control.kind == 3,
            "Unexpected outgoing port response"
        );
        anyhow::ensure!(
            number(control.body, 1)? == u64::from(self.client_id),
            "Wrong share client identity"
        );
        let server = u32::try_from(number(control.body, 2)?)?;
        let port = u16::try_from(number(control.body, 3)?)?;
        anyhow::ensure!(server != 0 && port != 0, "Invalid share peer port");
        let address = SocketAddr::new(peer.ip(), port);
        let socket = UdpSocket::bind(if peer.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        })?;
        socket.connect(address)?;
        socket.set_nonblocking(true)?;
        let mut reliable = kcp::Kcp::new(0x12345678, Output(socket.try_clone()?));
        reliable.set_nodelay(true, 20, 2, true);
        reliable.set_wndsize(32, 128);
        reliable.set_mtu(1400)?;
        let mut info = ft::tlv(3, 0, &server.to_be_bytes())?;
        info.extend(ft::tlv(3, 1, &1u32.to_be_bytes())?);
        info.extend(ft::tlv(3, 2, &0xff00u32.to_be_bytes())?);
        reliable.send(&ft::union(0, 0x100, &info)?)?;
        self.socket = Some(socket);
        self.reliable = Some(reliable);
        self.address = Some(address);
        self.activity = Instant::now();
        eprintln!("Mi Clip Share: peer port accepted; starting encrypted transfer channel");
        Ok(())
    }
    fn send(&mut self, message: &[u8]) -> anyhow::Result<()> {
        self.reliable
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Share transport unavailable"))?
            .send(&ft::seal(&self.key, message)?)?;
        Ok(())
    }
    fn manifest(&self) -> anyhow::Result<Vec<u8>> {
        let mut body = wire::integer(1, 1);
        body.extend(wire::message(3, self.task.as_bytes()));
        for (i, source) in self.request.offer.files.iter().enumerate() {
            let mut file = wire::message(1, source.name.as_bytes());
            file.extend(wire::integer(2, source.size));
            file.extend(wire::message(3, format!("{}-{i}", self.task).as_bytes()));
            body.extend(wire::message(5, &file));
        }
        let mut root = wire::integer(1, 1);
        root.extend(wire::message(2, &body));
        // The same bounded validator is used in both directions.
        crate::file_protocol::request(&root)?;
        Ok(root)
    }
    fn announce_streams(&mut self) -> anyhow::Result<()> {
        for index in 0..self.request.offer.files.len() {
            let id = index as u32 + 1;
            let file = self.request.offer.check(index)?;
            let mut body = ft::tlv(3, 0, &0u32.to_be_bytes())?;
            body.extend(ft::tlv(3, 1, &id.to_be_bytes())?);
            body.extend(ft::tlv(4, 2, &(file.size as i64).to_be_bytes())?);
            body.extend(ft::tlv(5, 3, file.mime.as_bytes())?);
            body.extend(ft::tlv(5, 4, file.name.as_bytes())?);
            body.extend(ft::tlv(5, 5, format!("{}-{index}", self.task).as_bytes())?);
            let express = ft::union(3, 0x100, &body)?;
            self.send(&ft::sdk_bytes(&express)?)?;
            self.streams.push((id, index, 0, false, false));
        }
        Ok(())
    }
    fn receive(&mut self, packet: &[u8]) -> anyhow::Result<()> {
        if ft::frame(packet).is_ok_and(|p| p.tag == 4) {
            // SDK server-info is plaintext; no file data is authorized by it.
            return Ok(());
        }
        let plaintext = ft::open(&self.key, packet)?;
        let frame = ft::frame(&plaintext)?;
        anyhow::ensure!(
            (frame.kind, frame.tag) == (0x100, 1),
            "Unsupported share event"
        );
        let fields = ft::nodes(frame.value)?;
        let express = node(&fields, 0, 5)?;
        let frame = ft::frame(express)?;
        match (frame.kind, frame.tag) {
            (0x100, 1) => {
                anyhow::ensure!(self.stream.is_none(), "Duplicate share socket offer");
                let fields = ft::nodes(frame.value)?;
                let port = u16::try_from(u32::from_be_bytes(node(&fields, 3, 3)?.try_into()?))?;
                let key: [u8; 16] = node(&fields, 4, 5)?.try_into()?;
                anyhow::ensure!(port != 0, "Invalid share data port");
                let address = SocketAddr::new(self.address.unwrap().ip(), port);
                let stream = TcpStream::connect_timeout(&address, Duration::from_secs(3))?;
                stream.set_nonblocking(true)?;
                self.stream = Some(stream);
                self.data_key = Some(key);
                self.send(&ft::byte_message(0, &self.manifest()?)?)?;
                self.announced = true;
                eprintln!("Mi Clip Share: file manifest sent; waiting for phone acceptance");
                self.request.status("waiting", 0)?;
            }
            (0x100, 2) => {
                if let Some(message) = self.assembler.push(express)? {
                    match number(&message, 1)? {
                        2 => {
                            anyhow::ensure!(
                                self.announced && !self.accepted,
                                "Unexpected share acceptance"
                            );
                            let response = bytes(&message, 2)?;
                            anyhow::ensure!(
                                number(response, 1)? == 1
                                    && bytes(response, 2)? == self.task.as_bytes(),
                                "Wrong share task"
                            );
                            anyhow::ensure!(
                                number(response, 3)? == 0,
                                "Phone declined file sharing"
                            );
                            self.accepted = true;
                            eprintln!("Mi Clip Share: phone accepted file manifest");
                            self.announce_streams()?;
                        }
                        8 => {
                            anyhow::ensure!(
                                self.accepted
                                    && number(bytes(&message, 2)?, 1)? == 1
                                    && self.streams.iter().all(|s| s.4)
                                    && self.pending.is_empty(),
                                "Premature share completion"
                            );
                            self.request.complete()?;
                            self.complete = true;
                        }
                        _ => anyhow::bail!("Phone cancelled or rejected file sharing"),
                    }
                }
            }
            (0x100, 4) => {
                let fields = ft::nodes(frame.value)?;
                let id = u32::from_be_bytes(node(&fields, 1, 3)?.try_into()?);
                anyhow::ensure!(
                    u32::from_be_bytes(node(&fields, 2, 3)?.try_into()?) == 2,
                    "Unsupported share transfer mode"
                );
                let stream = self
                    .streams
                    .iter_mut()
                    .find(|s| s.0 == id)
                    .ok_or_else(|| anyhow::anyhow!("Unknown share stream"))?;
                anyhow::ensure!(!stream.3, "Duplicate share stream request");
                stream.3 = true;
            }
            _ => anyhow::bail!("Unsupported share response"),
        }
        Ok(())
    }
    pub fn poll(&mut self) -> anyhow::Result<bool> {
        anyhow::ensure!(self.request.exists(), "Share cancelled");
        anyhow::ensure!(
            self.activity.elapsed() < Duration::from_secs(60)
                && (self.accepted || self.started.elapsed() < Duration::from_secs(600)),
            "Share timed out"
        );
        if let Some(socket) = self.socket.as_ref() {
            let mut buffer = [0; 65536];
            for _ in 0..32 {
                match socket.recv(&mut buffer) {
                    Ok(count) => {
                        ft::validate_datagram(&buffer[..count])?;
                        self.reliable.as_mut().unwrap().input(&buffer[..count])?;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) => return Err(e.into()),
                }
            }
        }
        if let Some(reliable) = self.reliable.as_mut() {
            reliable.update(self.started.elapsed().as_millis() as u32)?;
            reliable.flush_ack()?;
        }
        for _ in 0..8 {
            let Some(reliable) = self.reliable.as_mut() else {
                break;
            };
            let Ok(size) = reliable.peeksize() else {
                break;
            };
            anyhow::ensure!(size <= ft::MAX_PACKET, "Oversized share event");
            let mut packet = vec![0; size];
            reliable.recv(&mut packet)?;
            self.activity = Instant::now();
            self.receive(&packet)?;
        }
        if self.complete {
            return Ok(true);
        }
        if self.pending.is_empty() && self.accepted {
            if let Some(s) = self.streams.iter_mut().find(|s| s.3 && !s.4) {
                let bytes = self.request.offer.read(s.1, s.2)?;
                self.pending =
                    crate::file_stream::seal(self.data_key.as_ref().unwrap(), s.0, s.2, &bytes)?;
                s.2 += bytes.len() as u64;
                s.4 = bytes.is_empty();
                self.pending_offset = 0;
            }
        }
        if !self.pending.is_empty() {
            match self
                .stream
                .as_mut()
                .unwrap()
                .write(&self.pending[self.pending_offset..])
            {
                Ok(0) => anyhow::bail!("Share socket closed"),
                Ok(count) => {
                    self.pending_offset += count;
                    self.activity = Instant::now();
                    if self.pending_offset == self.pending.len() {
                        self.pending.clear();
                        self.request
                            .status("sending", self.streams.iter().map(|s| s.2).sum())?;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => (),
                Err(e) => return Err(e.into()),
            }
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn setup() -> (std::path::PathBuf, Sender) {
        let root = std::env::temp_dir().join(format!(
            "clip-share-test-{:016x}",
            u64::from_ne_bytes(crate::private::random().unwrap())
        ));
        let directory = root.join("outbox/test.ready");
        std::fs::create_dir_all(directory.join("files")).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(directory.join("files/sample.txt"), vec![0x42; 70_001]).unwrap();
        std::fs::write(directory.join("files/empty.bin"), b"").unwrap();
        std::fs::write(
            directory.join("request.json"),
            br#"{"files":["sample.txt","empty.bin"],"target":"127.0.0.1:1"}"#,
        )
        .unwrap();
        let request = crate::share_queue::Request::next(&root.join("outbox"))
            .unwrap()
            .unwrap();
        (root, Sender::new(request).unwrap())
    }
    #[test]
    fn direct_share_saves_multiple_files_and_waits_for_receiver_confirmation() {
        let (root, mut sender) = setup();
        let local = "127.0.0.1".parse().unwrap();
        let mut receiver = crate::file_channel::FileReceiver::open(
            local,
            local,
            None,
            sender.key,
            Some(&root.join("downloads")),
        )
        .unwrap();
        let port_request = sender.port_request().unwrap();
        let request = crate::file_channel::port_request(
            &crate::file_channel::control(&port_request).unwrap(),
        )
        .unwrap();
        crate::file_channel::PortBinding::from_user_info(
            bytes(bytes(&sender.logical_request(), 2).unwrap(), 3).unwrap(),
        )
        .unwrap()
        .verify(&request)
        .unwrap();
        let response =
            crate::file_channel::port_response(&request, 1, receiver.port().unwrap()).unwrap();
        sender
            .connect(
                &crate::file_channel::control(&response).unwrap(),
                SocketAddr::new(local, 1),
            )
            .unwrap();
        assert!(!sender.poll().unwrap());
        assert!(!root.join("downloads/sample.txt").exists());
        let deadline = Instant::now() + Duration::from_secs(8);
        while Instant::now() < deadline {
            receiver.poll().unwrap();
            if sender.poll().unwrap() {
                break;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(sender.complete, "share did not receive completion");
        assert_eq!(
            std::fs::read(root.join("downloads/sample.txt")).unwrap(),
            vec![0x42; 70_001]
        );
        assert_eq!(
            std::fs::metadata(root.join("downloads/empty.bin"))
                .unwrap()
                .len(),
            0
        );
        let state: serde_json::Value = serde_json::from_slice(
            &std::fs::read(root.join("outbox/test.ready/status.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(state["state"], "completed");
        drop(sender);
        drop(receiver);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn cancellation_and_premature_success_do_not_report_completion() {
        let (root, mut sender) = setup();
        let mut message = wire::integer(1, 8);
        message.extend(wire::message(2, &wire::integer(1, 1)));
        let complete = ft::byte_message(0, &message).unwrap();
        assert!(
            sender
                .receive(&ft::seal(&sender.key, &complete).unwrap())
                .is_err()
        );
        assert!(!sender.complete);
        std::fs::remove_dir_all(root.join("outbox/test.ready")).unwrap();
        assert!(sender.poll().is_err());
        drop(sender);
        std::fs::remove_dir_all(root).unwrap();
    }
}
