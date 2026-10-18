//! Bounded KCP message transport for negotiation. Single peer, no background thread.
use crate::wire;
use std::{
    collections::{BTreeMap, VecDeque},
    io,
    net::UdpSocket,
    time::{Duration, Instant},
};

const MTU: usize = 1200;
const LIMIT: usize = 131072;
struct Outbound {
    body: Vec<u8>,
    fragment: u8,
    sent: Option<Instant>,
}
pub struct Transport {
    socket: UdpSocket,
    start: Instant,
    send_next: u32,
    receive_next: u32,
    outbound: BTreeMap<u32, Outbound>,
    incoming: BTreeMap<u32, (u8, Vec<u8>)>,
    partial: Vec<u8>,
    fragments_left: Option<u8>,
    ready: VecDeque<Vec<u8>>,
}
impl Transport {
    pub fn new(socket: UdpSocket) -> anyhow::Result<Self> {
        socket.set_read_timeout(Some(Duration::from_millis(250)))?;
        Ok(Self {
            socket,
            start: Instant::now(),
            send_next: 0,
            receive_next: 0,
            outbound: BTreeMap::new(),
            incoming: BTreeMap::new(),
            partial: Vec::new(),
            fragments_left: None,
            ready: VecDeque::new(),
        })
    }
    pub fn send(&mut self, body: &[u8]) -> anyhow::Result<()> {
        anyhow::ensure!(
            !body.is_empty() && body.len() <= LIMIT,
            "Negotiation message exceeds limit"
        );
        let count = body.len().div_ceil(MTU - 24);
        anyhow::ensure!(
            self.outbound.len() + count <= 128,
            "Negotiation send window full"
        );
        anyhow::ensure!(
            self.send_next.checked_add(count as u32).is_some(),
            "Negotiation sequence exhausted"
        );
        for (i, chunk) in body.chunks(MTU - 24).enumerate() {
            self.outbound.insert(
                self.send_next,
                Outbound {
                    body: chunk.to_vec(),
                    fragment: (count - i - 1) as u8,
                    sent: None,
                },
            );
            self.send_next += 1;
        }
        self.flush()
    }
    fn flush(&mut self) -> anyhow::Result<()> {
        for (&sn, value) in &mut self.outbound {
            if value
                .sent
                .is_none_or(|t| t.elapsed() >= Duration::from_millis(350))
            {
                let mut packet = wire::packet(
                    81,
                    self.start.elapsed().as_millis() as u32,
                    sn,
                    self.receive_next,
                    &value.body,
                );
                packet[5] = value.fragment;
                self.socket.send(&packet)?;
                value.sent = Some(Instant::now());
            }
        }
        Ok(())
    }
    fn ingest(&mut self, input: &[u8]) -> anyhow::Result<()> {
        let Some(segments) = wire::segments(input) else {
            return Ok(());
        };
        for s in segments {
            if s.command == 82 {
                self.outbound.remove(&s.sequence);
            } else if s.command == 83 {
                self.socket
                    .send(&wire::packet(84, 0, 0, self.receive_next, &[]))?;
            } else if s.command == 81 {
                if s.sequence < self.receive_next || s.sequence - self.receive_next < 128 {
                    if s.sequence >= self.receive_next {
                        anyhow::ensure!(
                            s.body.len() <= 4096 && s.fragment < 128,
                            "Peer segment exceeds negotiation window"
                        );
                        let buffered: usize = self.incoming.values().map(|(_, b)| b.len()).sum();
                        anyhow::ensure!(
                            buffered + s.body.len() <= LIMIT,
                            "Peer receive buffer exceeds negotiation limit"
                        );
                        self.incoming
                            .entry(s.sequence)
                            .or_insert((s.fragment, s.body.to_vec()));
                    }
                    while let Some((fragment, bytes)) = self.incoming.remove(&self.receive_next) {
                        if let Some(expected) = self.fragments_left {
                            anyhow::ensure!(
                                fragment == expected,
                                "Invalid negotiation fragment sequence"
                            );
                        }
                        anyhow::ensure!(
                            self.partial.len() + bytes.len() <= LIMIT,
                            "Peer message exceeds negotiation limit"
                        );
                        self.partial.extend(bytes);
                        self.receive_next = self
                            .receive_next
                            .checked_add(1)
                            .ok_or_else(|| anyhow::anyhow!("Peer sequence exhausted"))?;
                        self.fragments_left = fragment.checked_sub(1);
                        if fragment == 0 {
                            anyhow::ensure!(self.ready.len() < 32, "Peer message queue full");
                            self.ready.push_back(std::mem::take(&mut self.partial));
                        }
                    }
                    self.socket.send(&wire::packet(
                        82,
                        s.timestamp,
                        s.sequence,
                        self.receive_next,
                        &[],
                    ))?;
                }
            }
        }
        Ok(())
    }
    pub fn receive(&mut self, deadline: Instant) -> anyhow::Result<Option<Vec<u8>>> {
        let mut buffer = [0; 65535];
        loop {
            if let Some(message) = self.ready.pop_front() {
                return Ok(Some(message));
            }
            let now = Instant::now();
            if now >= deadline {
                return Ok(None);
            }
            self.flush()?;
            self.socket
                .set_read_timeout(Some((deadline - now).min(Duration::from_millis(250))))?;
            match self.socket.recv(&mut buffer) {
                Ok(n) => self.ingest(&buffer[..n])?,
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
                    ) =>
                {
                    ()
                }
                Err(e) => return Err(e.into()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn idle_receive_respects_short_deadlines_for_other_channel_polling() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.connect(peer.local_addr().unwrap()).unwrap();
        let mut transport = Transport::new(socket).unwrap();
        assert!(
            transport
                .receive(Instant::now() + Duration::from_millis(30))
                .unwrap()
                .is_none()
        );
        assert!(transport.socket.read_timeout().unwrap().unwrap() <= Duration::from_millis(50));
    }
    #[test]
    fn reorders_fragments_and_ignores_duplicates() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.connect(peer.local_addr().unwrap()).unwrap();
        let mut t = Transport::new(socket).unwrap();
        let tail = wire::packet(81, 0, 1, 0, b"world");
        t.ingest(&tail).unwrap();
        t.ingest(&tail).unwrap();
        assert!(t.ready.is_empty());
        let mut head = wire::packet(81, 0, 0, 0, b"hello ");
        head[5] = 1;
        t.ingest(&head).unwrap();
        assert_eq!(t.ready.pop_front().unwrap(), b"hello world");
        t.ingest(&head).unwrap();
        assert!(t.ready.is_empty());
    }
    #[test]
    fn retransmits_until_acknowledged() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        socket.connect(peer.local_addr().unwrap()).unwrap();
        let mut t = Transport::new(socket).unwrap();
        t.send(b"synthetic").unwrap();
        let mut buffer = [0; 1400];
        let n = peer.recv(&mut buffer).unwrap();
        assert_eq!(wire::segments(&buffer[..n]).unwrap()[0].body, b"synthetic");
        t.outbound.get_mut(&0).unwrap().sent = Some(Instant::now() - Duration::from_secs(1));
        t.flush().unwrap();
        peer.recv(&mut buffer).unwrap();
        t.ingest(&wire::packet(82, 0, 0, 1, &[])).unwrap();
        assert!(t.outbound.is_empty());
    }
    #[test]
    fn rejects_inconsistent_fragment_count() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.connect(peer.local_addr().unwrap()).unwrap();
        let mut t = Transport::new(socket).unwrap();
        let mut first = wire::packet(81, 0, 0, 0, b"a");
        first[5] = 2;
        t.ingest(&first).unwrap();
        assert!(t.ingest(&wire::packet(81, 0, 1, 0, b"b")).is_err());
    }
}
