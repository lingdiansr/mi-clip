//! Initial same-account handshake research. A server hello is not authentication.
use crate::{
    account, private,
    transport::Transport,
    wire::{self, integer, message},
};
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::{SecretKey, elliptic_curve::sec1::ToEncodedPoint};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    net::{SocketAddr, UdpSocket},
    path::Path,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

fn nested<'a>(input: &'a [u8], path: &[u32]) -> anyhow::Result<&'a [u8]> {
    path.iter().try_fold(input, |bytes, &id| {
        wire::bytes_field(bytes, id).ok_or_else(|| anyhow::anyhow!("Missing handshake field"))
    })
}
fn number(input: &[u8], id: u32) -> anyhow::Result<u64> {
    wire::fields(input)
        .and_then(|fields| {
            fields.into_iter().find_map(|f| match f {
                wire::Field::Integer(n, v) if n == id => Some(v),
                _ => None,
            })
        })
        .ok_or_else(|| anyhow::anyhow!("Missing handshake integer"))
}
fn server_suites(notify: &[u8]) -> anyhow::Result<&[u8]> {
    let suites = nested(notify, &[1])?;
    anyhow::ensure!(
        number(suites, 1)? == 1 && number(suites, 3)? == 16 && number(suites, 4)? == 8,
        "Unsupported server cipher suite"
    );
    anyhow::ensure!(nested(suites, &[2])?.len() == 32, "Invalid server random");
    let public = nested(suites, &[5])?;
    let bytes = nested(public, &[2])?;
    anyhow::ensure!(
        number(public, 1)? == 1 && bytes.len() == 65 && bytes.first() == Some(&4),
        "Invalid server ephemeral key format"
    );
    Ok(suites)
}
fn frame(kind: u8, body: &[u8]) -> anyhow::Result<Vec<u8>> {
    let size = u16::try_from(body.len() + 4)?;
    let mut out = vec![kind, 4];
    out.extend(size.to_be_bytes());
    out.extend(body);
    Ok(out)
}
fn logical_encrypted(
    reply: &[u8],
    session_key: &[u8; 32],
    inner: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let iv = private::random::<12>()?;
    let mut encrypted = iv.to_vec();
    encrypted.extend(
        Aes256Gcm::new_from_slice(session_key)
            .unwrap()
            .encrypt(Nonce::from_slice(&iv), inner)
            .map_err(|_| anyhow::anyhow!("Logical message encryption failed"))?,
    );
    let incoming = nested(reply, &[2, 1])?;
    let mut logical = integer(1, number(incoming, 2)?);
    logical.extend(integer(2, number(incoming, 1)?));
    logical.extend(integer(3, number(incoming, 3)?));
    logical.extend(integer(4, 1));
    logical.extend(message(5, &encrypted));
    frame(17, &message(2, &message(1, &logical)))
}
fn networking_probe(
    config: &ProbeConfig,
    identity: &account::DeviceIdentity,
    session: &account::Session,
    key: &[u8; 32],
) -> anyhow::Result<Vec<u8>> {
    let did = URL_SAFE_NO_PAD.decode(&identity.did)?;
    let mut device = message(1, b"Mi Clip");
    device.extend(integer(2, 14));
    let device_id: String = did.iter().map(|b| format!("{b:02X}")).collect();
    let account_id: String = Sha256::digest(session.user_id.as_bytes())
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect();
    device.extend(message(3, device_id.as_bytes()));
    device.extend(message(4, account_id.as_bytes()));
    device.extend(integer(16, 2));
    device.extend(integer(18, 131072));
    // Networking's WLAN capability is 128; netbus's transport enum uses 256.
    device.extend(integer(21, 128));
    device.extend(message(23, device_id.as_bytes()));
    device.extend(integer(10, 5));
    let mut clipboard_service = message(1, b"universalClipboard");
    clipboard_service.extend(message(2, b"com.milink.service"));
    clipboard_service.extend(message(3, &[0]));
    device.extend(message(14, &clipboard_service));
    // The networking registry separately checks proof of account membership.
    // Sign a fresh challenge with our enrolled key, never a vendor-owned key.
    use base64::engine::general_purpose::STANDARD;
    use p256::ecdsa::{Signature, SigningKey, signature::Signer};
    use x509_cert::der::{DecodePem, Encode};
    let certificate_path = Path::new(&config.identity)
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Missing identity directory"))?
        .join("device-cert.pem");
    let certificate = x509_cert::Certificate::from_pem(&std::fs::read(certificate_path)?)?;
    let challenge = private::random::<32>()?;
    let signing = SigningKey::from_slice(&STANDARD.decode(&identity.private_key)?)?;
    let signature: Signature = signing.sign(&challenge);
    let mut cert_cred = message(1, &challenge);
    cert_cred.extend(message(2, &certificate.to_der()?));
    cert_cred.extend(message(3, signature.to_der().as_bytes()));
    let mut credential = integer(1, 3);
    credential.extend(message(4, &cert_cred));
    let mut group = integer(1, 1);
    group.extend(message(3, &credential));
    device.extend(message(15, &group));
    let mut sync = integer(1, 1);
    sync.extend(message(2, &device));
    let mut networking = integer(1, 1);
    networking.extend(integer(3, 1));
    networking.extend(message(5, &sync));
    let mut plaintext = vec![0];
    plaintext.extend(networking);
    encrypted_payload(key, &plaintext)
}
fn encrypted_payload(key: &[u8; 32], plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
    let iv = private::random::<12>()?;
    let mut body = vec![1, 1];
    body.extend(iv);
    body.extend(
        Aes256Gcm::new_from_slice(key)
            .unwrap()
            .encrypt(Nonce::from_slice(&iv), plaintext)
            .map_err(|_| anyhow::anyhow!("Networking message encryption failed"))?,
    );
    frame(0x29, &body)
}
fn verify_finished(
    secret: &SecretKey,
    random: &[u8],
    notify_reply: &[u8],
    finished_reply: &[u8],
) -> anyhow::Result<[u8; 32]> {
    let notify = nested(notify_reply, &[2, 1, 5, 7, 2, 6, 3])?;
    let suites = server_suites(notify)?;
    anyhow::ensure!(random.len() == 32, "Invalid client random");
    let public_bytes = nested(suites, &[5, 2])?;
    let peer = p256::PublicKey::from_sec1_bytes(public_bytes)?;
    let shared = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
    let mut context = random.to_vec();
    context.extend(nested(suites, &[2])?);
    // Protocol constant, identical for every account and device.
    let salt = [
        0x32, 0x9b, 0xfc, 0x53, 0x39, 0x36, 0x55, 0xd7, 0x5a, 0xb0, 0x83, 0x98, 0xca, 0x91, 0x91,
        0xef, 0xfa, 0xa3, 0x37, 0xf2, 0xe0, 0xbe, 0xb5, 0x73, 0xb1, 0xf9, 0xa3, 0xd0, 0x15, 0x57,
        0x64, 0x80,
    ];
    let mut session_key = [0; 32];
    hkdf::Hkdf::<Sha256>::new(Some(&salt), shared.raw_secret_bytes())
        .expand(&context, &mut session_key)
        .map_err(|_| anyhow::anyhow!("Session key derivation failed"))?;
    let encrypted = nested(finished_reply, &[2, 1, 5, 7, 2, 6, 5, 1])?;
    anyhow::ensure!(encrypted.len() >= 28, "Truncated server Finished");
    let plaintext = Aes256Gcm::new_from_slice(&session_key)
        .unwrap()
        .decrypt(Nonce::from_slice(&encrypted[..12]), &encrypted[12..])
        .map_err(|_| anyhow::anyhow!("Server Finished GCM verification failed"))?;
    let mut expected = shared.raw_secret_bytes().to_vec();
    expected.extend(public_bytes);
    anyhow::ensure!(
        plaintext == expected,
        "Server Finished key confirmation mismatch"
    );
    Ok(session_key)
}
pub fn verify_saved_finished(directory: &Path) -> anyhow::Result<()> {
    let secret = SecretKey::from_slice(&std::fs::read(directory.join("ephemeral-key.bin"))?)?;
    let random = std::fs::read(directory.join("client-random.bin"))?;
    let notify = std::fs::read(directory.join("reply-3.bin"))?;
    let finished = std::fs::read(directory.join("reply-4.bin"))?;
    let key = verify_finished(&secret, &random, &notify[4..], &finished[4..])?;
    private::save(&directory.join("session-key.bin"), &key)?;
    println!(
        "Server Finished authenticated and confirmed the independently derived session key. Clipboard sync remains unimplemented."
    );
    Ok(())
}
fn client_finished(
    config: &ProbeConfig,
    session: &account::Session,
    identity: &account::DeviceIdentity,
    secret: &SecretKey,
    reply: &[u8],
    info: &[u8],
) -> anyhow::Result<Vec<u8>> {
    use base64::engine::general_purpose::STANDARD;
    use p256::ecdsa::{Signature, SigningKey, signature::Signer};
    use x509_cert::der::{DecodePem, Encode};
    let notify = nested(reply, &[2, 1, 5, 7, 2, 6, 3])?;
    let server_public = nested(server_suites(notify)?, &[5, 2])?;
    let peer = p256::PublicKey::from_sec1_bytes(server_public)?;
    let shared = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
    let encrypted = nested(notify, &[2])?;
    anyhow::ensure!(encrypted.len() >= 28, "Truncated peer credential");
    let cipher = Aes256Gcm::new_from_slice(shared.raw_secret_bytes()).unwrap();
    let credential = cipher
        .decrypt(Nonce::from_slice(&encrypted[..12]), &encrypted[12..])
        .map_err(|_| anyhow::anyhow!("Peer credential GCM verification failed"))?;
    let client_public = secret.public_key().to_encoded_point(false);
    verify_credential(
        &credential,
        &std::fs::read(&config.account_certificate)?,
        &session.user_id,
        number(info, 5)?,
        server_public,
        client_public.as_bytes(),
    )?;
    let own_cert_path = Path::new(&config.identity)
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Missing identity directory"))?
        .join("device-cert.pem");
    let own_cert = x509_cert::Certificate::from_pem(&std::fs::read(own_cert_path)?)?;
    let signing = SigningKey::from_slice(&STANDARD.decode(&identity.private_key)?)?;
    anyhow::ensure!(
        certificate_key(&own_cert)? == *signing.verifying_key(),
        "Local certificate/key mismatch"
    );
    let mut signed = client_public.as_bytes().to_vec();
    signed.extend(server_public);
    let signature: Signature = signing.sign(&signed);
    let mut own_credential = message(1, &own_cert.to_der()?);
    own_credential.extend(message(2, signature.to_der().as_bytes()));
    let iv = private::random::<12>()?;
    let mut encrypted = iv.to_vec();
    encrypted.extend(
        cipher
            .encrypt(Nonce::from_slice(&iv), own_credential.as_slice())
            .map_err(|_| anyhow::anyhow!("Client credential encryption failed"))?,
    );
    let mut pair = integer(1, 3);
    pair.extend(message(4, &message(1, &encrypted)));
    let mut handshake = integer(1, 2);
    handshake.extend(integer(2, 4));
    handshake.extend(message(6, &pair));
    let mut auth = integer(1, 1);
    auth.extend(message(2, &handshake));
    let mut inner = integer(1, 6);
    inner.extend(message(7, &auth));
    let incoming = nested(reply, &[2, 1])?;
    let mut logical = integer(1, number(incoming, 2)?);
    logical.extend(integer(2, number(incoming, 1)?));
    logical.extend(integer(3, number(incoming, 3)?));
    logical.extend(message(5, &inner));
    frame(17, &message(2, &message(1, &logical)))
}
pub fn inspect(directory: &Path, output: &Path) -> anyhow::Result<()> {
    let secret = SecretKey::from_slice(&std::fs::read(directory.join("ephemeral-key.bin"))?)?;
    let reply = std::fs::read(directory.join("reply-3.bin"))?;
    anyhow::ensure!(reply.len() >= 4, "Truncated peer frame");
    let notify = nested(&reply[4..], &[2, 1, 5, 7, 2, 6, 3])?;
    let suites = nested(notify, &[1])?;
    let public = p256::PublicKey::from_sec1_bytes(nested(suites, &[5, 2])?)?;
    let shared = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), public.as_affine());
    let encrypted = nested(notify, &[2])?;
    anyhow::ensure!(encrypted.len() >= 28, "Truncated peer credential");
    let cipher = Aes256Gcm::new_from_slice(shared.raw_secret_bytes())
        .map_err(|_| anyhow::anyhow!("Invalid handshake key"))?;
    let credential = cipher
        .decrypt(Nonce::from_slice(&encrypted[..12]), &encrypted[12..])
        .map_err(|_| anyhow::anyhow!("Peer credential GCM authentication failed"))?;
    private::save(&output.join("credential.bin"), &credential)?;
    private::save(
        &output.join("server-certificate.der"),
        nested(&credential, &[1])?,
    )?;
    println!(
        "Peer credential decrypted with independently generated P256 key; certificate {} bytes, signature {} bytes. Trust verification remains required.",
        nested(&credential, &[1])?.len(),
        nested(&credential, &[2])?.len()
    );
    Ok(())
}

fn client_hello(public_key: &[u8], random: &[u8; 32]) -> Vec<u8> {
    let mut key = integer(1, 1);
    key.extend(message(2, public_key));
    let mut suites = integer(1, 1);
    suites.extend(message(2, random));
    suites.extend(integer(3, 16));
    suites.extend(integer(4, 8));
    suites.extend(message(5, &key));
    let mut notify = message(1, &suites);
    notify.extend(message(2, &integer(1, 1)));
    notify.extend(message(3, &integer(1, 1)));
    let mut pair = integer(1, 1);
    pair.extend(message(2, &notify));
    let mut frame = integer(1, 2);
    frame.extend(integer(2, 4));
    frame.extend(message(6, &pair));
    frame
}
fn sync_auth(uid: &str, salt: &[u8; 8], connection_nonce: u32, hello: &[u8]) -> Vec<u8> {
    let mut hash = Sha256::new();
    hash.update(salt);
    hash.update(Sha256::digest(uid.as_bytes()));
    let mut feature = message(1, salt);
    feature.extend(message(2, &hash.finalize()));
    let mut handshake = integer(1, 1);
    handshake.extend(message(2, hello));
    let mut auth_inner = integer(1, 6);
    auth_inner.extend(message(7, &handshake));
    let mut sync = integer(1, 10000);
    sync.extend(integer(2, 16));
    sync.extend(message(4, b"00150323"));
    sync.extend(message(5, &feature));
    sync.extend(message(8, &auth_inner));
    let mut inner = integer(1, 5);
    inner.extend(message(6, &sync));
    let mut logical = integer(1, 1);
    logical.extend(integer(3, u64::from(connection_nonce)));
    logical.extend(message(5, &inner));
    message(2, &message(1, &logical))
}
#[derive(Deserialize)]
struct ProbeConfig {
    #[serde(default = "default_endpoint")]
    endpoint: SocketAddr,
    session: String,
    identity: String,
    account_certificate: String,
    #[serde(default)]
    listen_seconds: Option<u64>,
    #[serde(default)]
    clipboard_sync: bool,
}
fn default_endpoint() -> SocketAddr {
    ([0, 0, 0, 0], 0).into()
}

fn certificate_key(cert: &x509_cert::Certificate) -> anyhow::Result<p256::ecdsa::VerifyingKey> {
    use p256::pkcs8::DecodePublicKey;
    use x509_cert::der::Encode;
    Ok(p256::ecdsa::VerifyingKey::from_public_key_der(
        &cert.tbs_certificate.subject_public_key_info.to_der()?,
    )?)
}
fn verify_credential(
    credential: &[u8],
    anchor: &[u8],
    uid: &str,
    peer_type: u64,
    server_public: &[u8],
    client_public: &[u8],
) -> anyhow::Result<()> {
    use p256::ecdsa::{Signature, signature::Verifier};
    use x509_cert::der::{Decode, DecodePem, Encode};
    let cert = x509_cert::Certificate::from_der(nested(credential, &[1])?)?;
    let anchor = x509_cert::Certificate::from_pem(anchor)?;
    anyhow::ensure!(
        cert.tbs_certificate.issuer == anchor.tbs_certificate.subject,
        "Peer certificate issuer mismatch"
    );
    anyhow::ensure!(
        cert.signature_algorithm == cert.tbs_certificate.signature
            && cert.signature_algorithm.oid.to_string() == "1.2.840.10045.4.3.2",
        "Unsupported peer certificate signature algorithm"
    );
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
    for item in [&cert, &anchor] {
        let validity = &item.tbs_certificate.validity;
        anyhow::ensure!(
            validity.not_before.to_unix_duration() <= now
                && now <= validity.not_after.to_unix_duration(),
            "Certificate is outside its validity period"
        );
    }
    let signature = cert
        .signature
        .as_bytes()
        .ok_or_else(|| anyhow::anyhow!("Invalid certificate signature bits"))?;
    certificate_key(&anchor)?
        .verify(
            &cert.tbs_certificate.to_der()?,
            &Signature::from_der(signature)?,
        )
        .map_err(|_| anyhow::anyhow!("Peer certificate signature verification failed"))?;
    let common_names: Vec<_> = cert
        .tbs_certificate
        .subject
        .0
        .iter()
        .flat_map(|r| r.0.iter())
        .filter(|a| a.oid.to_string() == "2.5.4.3")
        .collect();
    anyhow::ensure!(
        common_names.len() == 1,
        "Peer certificate common name is ambiguous"
    );
    let cn = std::str::from_utf8(common_names[0].value.value())?;
    let parts: Vec<_> = cn.split('.').collect();
    anyhow::ensure!(
        parts.len() == 4 && parts[0] == "lyra" && parts[3] == peer_type.to_string(),
        "Peer certificate device type mismatch"
    );
    // Android's stable certificate DID differs from its rotating four-byte advertisement DID.
    let did = URL_SAFE_NO_PAD.decode(parts[2])?;
    anyhow::ensure!(
        (4..=128).contains(&did.len()),
        "Invalid certificate device identity"
    );
    let expected_hash =
        URL_SAFE_NO_PAD.encode(Sha256::digest(format!("{}{uid}", parts[2]).as_bytes()));
    anyhow::ensure!(
        parts[1] == expected_hash,
        "Peer certificate belongs to a different account"
    );
    let mut signed = server_public.to_vec();
    signed.extend(client_public);
    certificate_key(&cert)?
        .verify(&signed, &Signature::from_der(nested(credential, &[2])?)?)
        .map_err(|_| anyhow::anyhow!("Peer ephemeral-key signature verification failed"))?;
    Ok(())
}
pub fn verify(config: &Path, directory: &Path) -> anyhow::Result<()> {
    let config: ProbeConfig = serde_json::from_slice(&std::fs::read(config)?)?;
    let session = account::read_session(Path::new(&config.session))?;
    let secret = SecretKey::from_slice(&std::fs::read(directory.join("ephemeral-key.bin"))?)?;
    let reply = std::fs::read(directory.join("reply-3.bin"))?;
    let notify = nested(&reply[4..], &[2, 1, 5, 7, 2, 6, 3])?;
    let public = nested(notify, &[1, 5, 2])?;
    let peer_public = p256::PublicKey::from_sec1_bytes(public)?;
    let shared = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), peer_public.as_affine());
    let encrypted = nested(notify, &[2])?;
    anyhow::ensure!(encrypted.len() >= 28, "Truncated peer credential");
    let cipher = Aes256Gcm::new_from_slice(shared.raw_secret_bytes()).unwrap();
    let credential = cipher
        .decrypt(Nonce::from_slice(&encrypted[..12]), &encrypted[12..])
        .map_err(|_| anyhow::anyhow!("Peer credential GCM verification failed"))?;
    let info_reply = std::fs::read(directory.join("reply-1.bin"))?;
    let info = nested(&info_reply[4..], &[2, 2, 4, 2])?;
    let peer_type = wire::fields(info)
        .and_then(|v| {
            v.into_iter().find_map(|f| match f {
                wire::Field::Integer(5, v) => Some(v),
                _ => None,
            })
        })
        .ok_or_else(|| anyhow::anyhow!("Missing peer device type"))?;
    verify_credential(
        &credential,
        &std::fs::read(config.account_certificate)?,
        &session.user_id,
        peer_type,
        public,
        secret.public_key().to_encoded_point(false).as_bytes(),
    )?;
    println!(
        "Independent Rust verification passed: account-issued certificate, validity, same account/device and signed ephemeral keys."
    );
    Ok(())
}
pub fn save_endpoints(path: &Path, endpoints: &[crate::discovery::Endpoint]) -> anyhow::Result<()> {
    private::save(path, &serde_json::to_vec(endpoints)?)
}

/// Configuration and raw replies stay in a private research directory.
#[derive(Clone, Copy, Debug)]
pub enum SyncEvent {
    Connected,
    Received(usize),
    Sent(usize),
    Unsupported,
}

pub fn probe(config: &Path, directory: &Path) -> anyhow::Result<()> {
    exchange(config, Some(directory), None, &|_| {})
}

#[cfg(feature = "clipboard")]
pub fn sync_once(
    config: &Path,
    stop: &std::sync::atomic::AtomicBool,
    on_event: &dyn Fn(SyncEvent),
) -> anyhow::Result<()> {
    exchange(config, None, Some(stop), on_event)
}

fn exchange(
    config: &Path,
    directory: Option<&Path>,
    stop: Option<&std::sync::atomic::AtomicBool>,
    on_event: &dyn Fn(SyncEvent),
) -> anyhow::Result<()> {
    macro_rules! diagnostic { ($($arg:tt)*) => { if directory.is_some() { println!($($arg)*); } }; }
    let base = config.canonicalize()?.parent().unwrap().to_path_buf();
    let mut config: ProbeConfig = serde_json::from_slice(&std::fs::read(config)?)?;
    for value in [
        &mut config.session,
        &mut config.identity,
        &mut config.account_certificate,
    ] {
        if Path::new(value).is_relative() {
            *value = base.join(&*value).to_string_lossy().into_owned();
        }
    }
    if stop.is_some() {
        config.clipboard_sync = true;
    }
    if stop.is_some() {
        use std::net::ToSocketAddrs;
        if let Ok(endpoints) = crate::discovery::discover(Duration::from_secs(3)) {
            if let Some(address) = endpoints
                .iter()
                .filter(|e| e.device_type == 1)
                .filter_map(|e| (e.host.as_str(), e.kcp_port).to_socket_addrs().ok())
                .flatten()
                .find(|a| a.is_ipv4())
            {
                config.endpoint = address;
            }
        }
    }
    anyhow::ensure!(config.endpoint.port() != 0, "No phone discovered");
    let save = |name: &str, bytes: &[u8]| -> anyhow::Result<()> {
        if let Some(directory) = directory {
            private::save(&directory.join(name), bytes)?;
        }
        Ok(())
    };
    let session = account::read_session(Path::new(&config.session))?;
    let identity: account::DeviceIdentity =
        serde_json::from_slice(&std::fs::read(&config.identity)?)?;
    let did = URL_SAFE_NO_PAD.decode(&identity.did)?;
    anyhow::ensure!(did.len() == 4, "Invalid local device identity");
    let key = loop {
        if let Ok(key) = SecretKey::from_slice(&private::random::<32>()?) {
            break key;
        }
    };
    let random = private::random::<32>()?;
    let hello = client_hello(key.public_key().to_encoded_point(false).as_bytes(), &random);
    let auth = sync_auth(
        &session.user_id,
        &private::random()?,
        u32::from_be_bytes(private::random()?),
        &hello,
    );
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64;
    let request = wire::sync_request_with_auth(
        u32::from_be_bytes(did.try_into().unwrap()),
        u32::from_be_bytes(private::random()?),
        now,
        Some(&auth),
    );
    let bind = if config.endpoint.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind)?;
    socket.connect(config.endpoint)?;
    let mut transport = Transport::new(socket)?;
    save("client-random.bin", &random)?;
    save("ephemeral-key.bin", &key.to_bytes())?;
    save("request.bin", &request)?;
    transport.send(&request)?;
    let started = Instant::now();
    let deadline = started
        + Duration::from_secs(if stop.is_some() {
            86400
        } else {
            config.listen_seconds.unwrap_or(15).clamp(1, 900)
        });
    let mut last_received = started;
    let mut count = 0;
    let mut info = None;
    let mut finished_sent = false;
    let mut server_notify = None;
    let mut authenticated = false;
    let mut active_key = None;
    anyhow::ensure!(
        !config.clipboard_sync || cfg!(feature = "clipboard"),
        "Clipboard feature required"
    );
    #[cfg(feature = "clipboard")]
    let mut clipboard_count = if config.clipboard_sync {
        crate::clipboard::change_count()
    } else {
        0
    };
    #[cfg(feature = "clipboard")]
    let mut last_text: Option<String> = None;
    #[cfg(feature = "clipboard")]
    let mut sequence = private::random::<1>()?[0];
    #[cfg(feature = "clipboard")]
    let mut network_ready = false;
    while Instant::now() < deadline {
        if stop.is_some_and(|s| s.load(std::sync::atomic::Ordering::Relaxed)) {
            break;
        }
        anyhow::ensure!(
            authenticated || started.elapsed() < Duration::from_secs(20),
            "Phone authentication timed out"
        );
        anyhow::ensure!(
            last_received.elapsed() < Duration::from_secs(120),
            "Phone connection timed out"
        );
        #[cfg(feature = "clipboard")]
        if config.clipboard_sync && network_ready && active_key.is_some() {
            if crate::clipboard::change_count() != clipboard_count {
                let (count, text) = crate::clipboard::read();
                clipboard_count = count;
                if let Some(text) = text.filter(|t| Some(t) != last_text.as_ref()) {
                    sequence = sequence.wrapping_add(1);
                    if let Some(payload) = crate::message_center::text_payload(&text, sequence) {
                        transport
                            .send(&encrypted_payload(active_key.as_ref().unwrap(), &payload)?)?;
                        on_event(SyncEvent::Sent(text.len()));
                        diagnostic!(
                            "Mac → phone: encrypted text sent, {} bytes; delivery needs phone verification.",
                            text.len()
                        );
                    } else {
                        on_event(SyncEvent::Unsupported);
                        diagnostic!(
                            "Clipboard content skipped: empty or beyond inline text limit."
                        );
                    }
                    last_text = Some(text);
                }
            }
        }
        let slice = if config.clipboard_sync {
            deadline.min(Instant::now() + Duration::from_millis(250))
        } else {
            deadline
        };
        let Some(reply) = transport.receive(slice)? else {
            continue;
        };
        last_received = Instant::now();
        count += 1;
        save(&format!("reply-{count}.bin"), &reply)?;
        diagnostic!(
            "Peer negotiation reply received: {} bytes; contents saved privately.",
            reply.len()
        );
        anyhow::ensure!(reply.len() >= 4, "Truncated peer frame");
        if let Ok(device) = nested(&reply[4..], &[2, 2, 4, 2]) {
            info = Some(device.to_vec());
        }
        if !finished_sent && nested(&reply[4..], &[2, 1, 5, 7, 2, 6, 3]).is_ok() {
            let finished = client_finished(
                &config,
                &session,
                &identity,
                &key,
                &reply[4..],
                info.as_deref()
                    .ok_or_else(|| anyhow::anyhow!("Missing peer device info"))?,
            )?;
            save("client-finished.bin", &finished)?;
            transport.send(&finished)?;
            finished_sent = true;
            server_notify = Some(reply[4..].to_vec());
            diagnostic!(
                "Peer certificate and ephemeral signature verified. Independent client certificate and signature sent."
            );
        }
        if nested(&reply[4..], &[2, 1, 5, 7, 2, 6, 5]).is_ok() {
            let session_key = verify_finished(
                &key,
                &random,
                server_notify
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("Unexpected server Finished"))?,
                &reply[4..],
            )?;
            save("session-key.bin", &session_key)?;
            authenticated = true;
            active_key = Some(session_key);
            diagnostic!(
                "Phone accepted independent client identity; server Finished and session key confirmation verified."
            );
            let mut request = message(2, b"00150323");
            request.extend(integer(4, 16));
            request.extend(integer(5, 10000));
            request.extend(integer(6, 256));
            request.extend(integer(7, 1));
            let mut inner = integer(1, 1);
            inner.extend(message(2, &request));
            let packet = logical_encrypted(&reply[4..], &session_key, &inner)?;
            save("connection-request.bin", &packet)?;
            transport.send(&packet)?;
        }
        if let (Some(session_key), Ok(logical)) =
            (active_key.as_ref(), nested(&reply[4..], &[2, 1]))
        {
            if number(logical, 4).unwrap_or(0) == 1 {
                let encrypted = nested(logical, &[5])?;
                anyhow::ensure!(encrypted.len() >= 28, "Truncated encrypted logical frame");
                let plaintext = Aes256Gcm::new_from_slice(session_key)
                    .unwrap()
                    .decrypt(Nonce::from_slice(&encrypted[..12]), &encrypted[12..])
                    .map_err(|_| anyhow::anyhow!("Logical frame authentication failed"))?;
                save(&format!("logical-{count}.bin"), &plaintext)?;
                diagnostic!(
                    "Authenticated logical response received: {} bytes, protocol type {}.",
                    plaintext.len(),
                    number(&plaintext, 1)?
                );
                if number(&plaintext, 1)? == 2 {
                    let response = nested(&plaintext, &[3])?;
                    anyhow::ensure!(
                        number(response, 1).unwrap_or(0) == 0,
                        "Phone rejected logical connection"
                    );
                    let mut ack = integer(1, 3);
                    ack.extend(message(4, &[]));
                    transport.send(&logical_encrypted(&reply[4..], session_key, &ack)?)?;
                    diagnostic!("Encrypted logical connection accepted; acknowledgement sent.");
                    transport.send(&networking_probe(
                        &config,
                        &identity,
                        &session,
                        session_key,
                    )?)?;
                    #[cfg(feature = "clipboard")]
                    {
                        network_ready = true;
                    }
                    on_event(SyncEvent::Connected);
                }
            }
        }
        if let Ok(heartbeat) = nested(&reply[4..], &[2, 2, 6]) {
            let mut physical = integer(2, 5);
            physical.extend(message(7, heartbeat));
            transport.send(&frame(9, &message(2, &message(2, &physical)))?)?;
        }
        if reply[0] == 0x29 && reply.len() >= 34 {
            if let Some(key) = active_key.as_ref() {
                anyhow::ensure!(
                    reply[4] == 1 && reply[5] == 1,
                    "Unexpected networking destination or encryption mode"
                );
                let plaintext = Aes256Gcm::new_from_slice(key)
                    .unwrap()
                    .decrypt(Nonce::from_slice(&reply[6..18]), &reply[18..])
                    .map_err(|_| anyhow::anyhow!("Networking response authentication failed"))?;
                save(&format!("payload-{count}.bin"), &plaintext)?;
                #[cfg(feature = "clipboard")]
                if config.clipboard_sync {
                    if let Some(text) = crate::message_center::payload_text(&plaintext) {
                        if last_text.as_deref() != Some(text) {
                            clipboard_count = crate::clipboard::write(text)?;
                            last_text = Some(text.to_owned());
                            on_event(SyncEvent::Received(text.len()));
                            diagnostic!(
                                "Phone → Mac: text written to native clipboard, {} bytes.",
                                text.len()
                            );
                        }
                    }
                }
                if plaintext.first() == Some(&1) {
                    if let Ok(packet) = nested(&plaintext[1..], &[8, 1]) {
                        if let Some(topics) = crate::message_center::decode(packet) {
                            for topic in topics {
                                diagnostic!(
                                    "Authenticated topic: {}; base {} bytes; extension {} bytes. Contents remain private.",
                                    crate::message_center::topic_name(topic.id),
                                    topic.base.len(),
                                    topic.extension.len()
                                );
                            }
                        } else {
                            diagnostic!("Unsupported or malformed message-center record; ignored.");
                        }
                    }
                }
                diagnostic!(
                    "Encrypted service payload authenticated: {} bytes.",
                    plaintext.len()
                );
            }
        }
        anyhow::ensure!(
            stop.is_some() || count <= 512,
            "Negotiation reply limit reached"
        );
    }
    anyhow::ensure!(
        count > 0,
        "Phone negotiation timed out; authentication not established"
    );
    diagnostic!(
        "Exchange ended. Authenticated: {authenticated}; clipboard enabled: {}.",
        config.clipboard_sync
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_unoffered_server_suites_and_invalid_key_formats() {
        let key = SecretKey::from_slice(&[1; 32]).unwrap();
        let public = key.public_key().to_encoded_point(false);
        let notify = |version, protocol, cipher, random_len, key_type, bytes: &[u8]| {
            let mut suite = integer(1, version);
            suite.extend(message(2, &vec![2; random_len]));
            suite.extend(integer(3, protocol));
            suite.extend(integer(4, cipher));
            let mut pk = integer(1, key_type);
            pk.extend(message(2, bytes));
            suite.extend(message(5, &pk));
            message(1, &suite)
        };
        assert!(server_suites(&notify(1, 16, 8, 32, 1, public.as_bytes())).is_ok());
        for invalid in [
            notify(2, 16, 8, 32, 1, public.as_bytes()),
            notify(1, 8, 16, 32, 1, public.as_bytes()),
            notify(1, 16, 8, 31, 1, public.as_bytes()),
            notify(1, 16, 8, 32, 2, public.as_bytes()),
            notify(1, 16, 8, 32, 1, &public.as_bytes()[..64]),
        ] {
            assert!(server_suites(&invalid).is_err());
        }
    }
    #[test]
    fn hello_uses_uncompressed_p256_and_same_account_suite() {
        let key = SecretKey::from_slice(&[1; 32]).unwrap();
        let public = key.public_key().to_encoded_point(false);
        let hello = client_hello(public.as_bytes(), &[2; 32]);
        let pair = wire::bytes_field(&hello, 6).unwrap();
        let notify = wire::bytes_field(pair, 2).unwrap();
        let suites = wire::bytes_field(notify, 1).unwrap();
        let fields = wire::fields(suites).unwrap();
        assert!(fields.contains(&wire::Field::Integer(3, 16)));
        assert!(fields.contains(&wire::Field::Integer(4, 8)));
        let public_field = wire::bytes_field(suites, 5).unwrap();
        assert_eq!(
            wire::bytes_field(public_field, 2).unwrap(),
            public.as_bytes()
        );
    }
}
