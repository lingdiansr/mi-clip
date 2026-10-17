use mi_clip::wire;
use std::{
    collections::BTreeMap,
    fs::File,
    io::{self, Read},
    net::{ToSocketAddrs, UdpSocket},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub fn run(host: &str, port: u16) -> anyhow::Result<()> {
    anyhow::ensure!(port != 0, "Port must be nonzero");
    let remote = (host, port)
        .to_socket_addrs()?
        .find(|ip| ip.is_ipv4())
        .ok_or_else(|| anyhow::anyhow!("IPv4 endpoint not found"))?;
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(remote)?;
    socket.set_read_timeout(Some(Duration::from_millis(200)))?;
    let mut random = [0_u8; 8];
    File::open("/dev/urandom")?.read_exact(&mut random)?;
    let device = u32::from_be_bytes(random[..4].try_into()?);
    let connection = u32::from_be_bytes(random[4..].try_into()?);
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64;
    let request = wire::sync_request(device, connection, now);
    let start = Instant::now();
    let mut last_send = None;
    let mut acknowledged = false;
    let mut next = 0;
    let mut pending = BTreeMap::new();
    let mut body = Vec::new();
    let mut buffer = [0_u8; 65535];
    while start.elapsed() < Duration::from_secs(6) {
        if !acknowledged
            && last_send.is_none_or(|when: Instant| when.elapsed() >= Duration::from_secs(1))
        {
            socket.send(&wire::packet(
                81,
                start.elapsed().as_millis() as u32,
                0,
                next,
                &request,
            ))?;
            last_send = Some(Instant::now());
        }
        let n = match socket.recv(&mut buffer) {
            Ok(n) => n,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::TimedOut
                        | io::ErrorKind::WouldBlock
                        | io::ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        let Some(segments) = wire::segments(&buffer[..n]) else {
            continue;
        };
        for s in segments {
            if s.command == 82 && s.sequence == 0 {
                acknowledged = true;
            }
            if s.command != 81 {
                continue;
            }
            if s.sequence >= next && s.sequence < next + 128 && pending.len() < 128 {
                pending
                    .entry(s.sequence)
                    .or_insert((s.fragment, s.body.to_vec()));
            }
            while let Some((fragment, bytes)) = pending.remove(&next) {
                next += 1;
                body.extend(bytes);
                anyhow::ensure!(body.len() <= 131072, "Reply exceeds negotiation limit");
                if fragment == 0 {
                    if wire::device_info(&body).is_some() {
                        socket.send(&wire::packet(82, s.timestamp, s.sequence, next, &[]))?;
                        println!(
                            "Independent Rust device-info negotiation passed. Device identifiers omitted. Clipboard authentication and sync remain unimplemented."
                        );
                        return Ok(());
                    }
                    body.clear();
                }
            }
            socket.send(&wire::packet(82, s.timestamp, s.sequence, next, &[]))?;
        }
    }
    anyhow::bail!("Device-info negotiation timed out; no clipboard connection established")
}
