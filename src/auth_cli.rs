use crate::account;
use std::path::Path;
pub fn run(a: &[String]) -> anyhow::Result<()> {
    #[cfg(feature = "research")]
    if a.len() == 6 && a[0] == "receive-file-capture" {
        let input = std::fs::read(&a[1])?;
        let stream = std::fs::read(&a[2])?;
        let key: [u8; 16] = std::fs::read(&a[3])?
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid file data key length"))?;
        let capture = std::fs::read(&a[4])?;
        anyhow::ensure!(
            capture.len() <= 4 * 1024 * 1024,
            "Oversized private file capture"
        );
        let manifest = crate::file_protocol::request(&input)?;
        let offer = crate::file_transport::stream_offer(&stream)?
            .ok_or_else(|| anyhow::anyhow!("Not a file stream offer"))?;
        let file = manifest
            .files
            .iter()
            .find(|f| {
                f.name == offer.name
                    && f.id == offer.tag
                    && offer.length.is_none_or(|length| f.size == length)
            })
            .ok_or_else(|| anyhow::anyhow!("File stream is not bound to accepted manifest"))?;
        let mut output =
            crate::file_stream::Receiver::new(offer.id, Path::new(&a[5]), file.name, file.size)?;
        let mut rest = capture.as_slice();
        let mut finished = false;
        while !rest.is_empty() {
            anyhow::ensure!(!finished, "Unexpected data after file stream end");
            let size = crate::file_stream::record_size(rest)?;
            anyhow::ensure!(size <= rest.len(), "Truncated file capture record");
            let chunk = crate::file_stream::open(&key, &rest[..size])?;
            finished = output.push(chunk)?;
            rest = &rest[size..];
        }
        anyhow::ensure!(finished, "File capture has no authenticated end record");
        println!(
            "One file authenticated, length/offset/end verified and atomically saved: {} bytes. No file name or content printed.",
            file.size
        );
        return Ok(());
    }
    #[cfg(feature = "research")]
    if a.len() == 3 && a[0] == "verify-file-stream" {
        let input = std::fs::read(&a[1])?;
        let stream = std::fs::read(&a[2])?;
        let manifest = crate::file_protocol::request(&input)?;
        let offer = crate::file_transport::stream_offer(&stream)?
            .ok_or_else(|| anyhow::anyhow!("Not a file stream request"))?;
        anyhow::ensure!(
            manifest.files.iter().any(|f| f.name == offer.name
                && f.id == offer.tag
                && offer.length.is_none_or(|length| f.size == length)),
            "Stream differs from file manifest"
        );
        crate::file_transport::stream_begin(offer.id)?;
        println!(
            "Saved authenticated stream matches manifest name, ID and bounded size; unknown stream length is resolved from manifest. No identifiers printed."
        );
        return Ok(());
    }
    #[cfg(feature = "research")]
    if a.len() == 2 && a[0] == "verify-file-manifest" {
        let input = std::fs::read(&a[1])?;
        let manifest = crate::file_protocol::request(&input)?;
        let response = crate::file_protocol::accept(&manifest);
        crate::file_transport::byte_message(0, &response)?;
        println!(
            "Saved file manifest and acceptance encoding verified: {} files, {} bytes total. No names or identifiers printed.",
            manifest.files.len(),
            manifest.files.iter().map(|f| f.size).sum::<u64>()
        );
        return Ok(());
    }
    #[cfg(feature = "research")]
    if a.len() == 4 && a[0] == "open-file-message" {
        let control = std::fs::read(&a[1])?;
        let message = std::fs::read(&a[2])?;
        let request = crate::file_channel::port_request(&crate::file_channel::control(&control)?)?;
        let plaintext = crate::file_transport::open(&request.transfer_key, &message)?;
        crate::private::save(Path::new(&a[3]), &plaintext)?;
        println!(
            "Saved bulk message authenticated and decrypted privately: {} bytes. No content printed.",
            plaintext.len()
        );
        return Ok(());
    }
    #[cfg(feature = "research")]
    if a.len() == 2 && a[0] == "verify-file-event" {
        let packet = std::fs::read(&a[1])?;
        anyhow::ensure!(packet.len() <= 4096, "Oversized saved file event");
        anyhow::ensure!(
            crate::file_transport::negotiation_reply(&packet, 1)?.is_some(),
            "Not a bulk event negotiation request"
        );
        println!(
            "Saved file event framing and negotiation reply verified. No socket opened; no identifiers printed."
        );
        return Ok(());
    }
    #[cfg(feature = "research")]
    if a.len() == 3 && a[0] == "verify-file-port" {
        let logical = std::fs::read(&a[1])?;
        let packet = std::fs::read(&a[2])?;
        anyhow::ensure!(
            logical.len() <= 4096 && packet.len() <= 1024,
            "Oversized saved file control"
        );
        let request = crate::wire::bytes_field(&logical, 2)
            .ok_or_else(|| anyhow::anyhow!("Missing saved logical request"))?;
        let user = crate::wire::bytes_field(request, 3)
            .ok_or_else(|| anyhow::anyhow!("Missing saved bulk user info"))?;
        let binding = crate::file_channel::PortBinding::from_user_info(user)?;
        let request = crate::file_channel::port_request(&crate::file_channel::control(&packet)?)?;
        binding.verify(&request)?;
        crate::file_channel::port_response(&request, 1, 12345)?;
        println!(
            "Saved file-port parsing and authenticated key binding verified. No socket opened; no identifiers printed."
        );
        return Ok(());
    }
    if a.len() == 4 && a[0] == "verify-file-request" {
        return crate::handshake::verify_file_request(
            Path::new(&a[1]),
            Path::new(&a[2]),
            Path::new(&a[3]),
        );
    }
    if a.len() == 2 && a[0] == "inspect-services" {
        let bytes = std::fs::read(&a[1])?;
        let peer = crate::networking::peer(&bytes)
            .ok_or_else(|| anyhow::anyhow!("Unsupported device capability message"))?;
        println!(
            "Authenticated device capabilities: type {}; {} services; native file sharing: {}. No device names or identifiers printed.",
            peer.device_type,
            peer.services.len(),
            peer.can_share_files()
        );
        return Ok(());
    }
    if a.len() == 2 && a[0] == "apply-payload" {
        let bytes = std::fs::read(&a[1])?;
        let text = crate::message_center::payload_text(&bytes).ok_or_else(|| {
            anyhow::anyhow!("Payload is not a supported inline text clipboard event")
        })?;
        crate::clipboard::write(text)?;
        anyhow::ensure!(
            crate::clipboard::read().1.as_deref() == Some(text),
            "Clipboard readback mismatch"
        );
        println!(
            "Phone text written to macOS clipboard and read back exactly: {} bytes. No content printed.",
            text.len()
        );
        return Ok(());
    }
    if a.len() == 2 && a[0] == "inspect-topic" {
        let bytes = std::fs::read(&a[1])?;
        let topics = crate::message_center::decode(&bytes)
            .ok_or_else(|| anyhow::anyhow!("Unsupported or malformed topic packet"))?;
        for topic in topics {
            println!(
                "Topic: {}; base {} bytes; extension {} bytes. No content printed.",
                crate::message_center::topic_name(topic.id),
                topic.base.len(),
                topic.extension.len()
            );
        }
        return Ok(());
    }
    if a.len() == 2 && a[0] == "discover" {
        let endpoints = crate::discovery::discover(std::time::Duration::from_secs(8))?;
        let phones = endpoints.iter().filter(|e| e.device_type == 1).count();
        crate::handshake::save_endpoints(Path::new(&a[1]), &endpoints)?;
        println!(
            "Independent Rust discovery: {} endpoints, {} phones; addresses saved privately.",
            endpoints.len(),
            phones
        );
        return Ok(());
    }
    if a.len() == 2 && a[0] == "verify-finished" {
        return crate::handshake::verify_saved_finished(Path::new(&a[1]));
    }
    if a.len() == 2 && a[0] == "self-test-csr" {
        let identity = account::DeviceIdentity {
            private_key: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=".into(),
            did: "AQIDBA".into(),
        };
        let csr = account::device_csr(&identity, "1234")?;
        std::fs::write(&a[1], csr)?;
        println!("Synthetic CSR fixture generated.");
        return Ok(());
    }
    anyhow::ensure!(
        a.len() == 3,
        "usage: mi-clip-auth prepare|poll|redeem|account-cert|device-cert|probe-handshake INPUT OUTPUT"
    );
    let input = Path::new(&a[1]);
    let output = Path::new(&a[2]);
    match a[0].as_str() {
        "prepare" => account::prepare_qr(input, output)?,
        "poll" => account::poll_qr(input, output)?,
        "redeem" => account::redeem_grant(input, output)?,
        "account-cert" => account::account_certificate(&account::read_session(input)?, output)?,
        "device-cert" => account::device_certificate(&account::read_session(input)?, output)?,
        "probe-handshake" => crate::handshake::probe(input, output)?,
        "inspect-handshake" => crate::handshake::inspect(input, output)?,
        "verify-handshake" => crate::handshake::verify(input, output)?,
        "sign-update" => crate::updater::sign_release(input, output)?,
        _ => anyhow::bail!("Unknown authorization command"),
    }
    println!(
        "Independent Rust authorization operation completed; private output saved. No credentials printed."
    );
    Ok(())
}
