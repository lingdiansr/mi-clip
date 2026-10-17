use crate::account;
use std::path::Path;
pub fn run(a: &[String]) -> anyhow::Result<()> {
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
