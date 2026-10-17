//! Independent Xiaomi authorization and certificate enrollment.
//! Credentials have no Debug implementation and never appear in error messages.
use crate::{http, private};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    pkcs8::EncodePublicKey,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::{
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Serialize, Deserialize)]
pub struct Session {
    pub sid: String,
    #[serde(rename = "userId")]
    pub user_id: String,
    #[serde(rename = "cUserId")]
    pub c_user_id: String,
    pub ssecurity: String,
    #[serde(rename = "serviceToken")]
    pub service_token: String,
}
#[derive(Serialize, Deserialize)]
pub struct QrSession {
    sid: String,
    #[serde(rename = "pollURL")]
    poll_url: String,
    #[serde(rename = "expiresAt")]
    expires_at: f64,
}
#[derive(Serialize, Deserialize)]
pub struct DeviceIdentity {
    #[serde(rename = "privateKey")]
    pub private_key: String,
    pub did: String,
}
fn timestamp() -> anyhow::Result<f64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64())
}
fn check_code(value: &Value) -> anyhow::Result<()> {
    let code = value
        .get("code")
        .and_then(Value::as_i64)
        .ok_or_else(|| anyhow::anyhow!("Account response has no code"))?;
    anyhow::ensure!(
        code == 0,
        "Account service response code {code}; details omitted"
    );
    Ok(())
}
pub fn json_response(bytes: &[u8]) -> anyhow::Result<Value> {
    let data = bytes.strip_prefix(b"&&&START&&&").unwrap_or(bytes);
    serde_json::from_slice(data).map_err(|_| anyhow::anyhow!("Invalid account JSON response"))
}
fn account_url(value: &str) -> anyhow::Result<url::Url> {
    let url = url::Url::parse(value).map_err(|_| anyhow::anyhow!("Invalid account URL"))?;
    let host = url.host_str().unwrap_or("");
    anyhow::ensure!(
        url.scheme() == "https"
            && (host == "account.xiaomi.com" || host.ends_with(".account.xiaomi.com"))
            && url.username().is_empty()
            && url.password().is_none()
            && url.port_or_known_default() == Some(443),
        "Unexpected account URL"
    );
    Ok(url)
}
fn string<'a>(value: &'a Value, key: &str) -> anyhow::Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("Account response missing required field"))
}
pub fn prepare_qr(state_path: &Path, qr_path: &Path) -> anyhow::Result<()> {
    anyhow::ensure!(
        state_path != qr_path,
        "Distinct session and QR paths required"
    );
    let r = http::request(
        "https://account.xiaomi.com/longPolling/loginUrl?sid=miconnect&_json=true",
        None,
        &[("User-Agent", "Mozilla/5.0 MiClip")],
        15,
    )?;
    anyhow::ensure!(r.status == 200, "Account HTTP status {}", r.status);
    let response = json_response(&r.body)?;
    check_code(&response)?;
    let login = account_url(string(&response, "loginUrl")?)?;
    let poll = account_url(string(&response, "lp")?)?;
    let duration = response["timeout"]
        .as_f64()
        .unwrap_or(300.0)
        .clamp(1.0, 300.0);
    let state = QrSession {
        sid: "miconnect".into(),
        poll_url: poll.to_string(),
        expires_at: timestamp()? + duration,
    };
    private::save(state_path, &serde_json::to_vec(&state)?)?;
    write_qr(login.as_str(), qr_path)?;
    Ok(())
}
fn write_qr(value: &str, output: &Path) -> anyhow::Result<()> {
    let code = qrcode::QrCode::with_error_correction_level(value, qrcode::EcLevel::M)?;
    let side = (code.width() + 8) * 8;
    let mut pixels = vec![255_u8; side * side];
    for y in 0..code.width() {
        for x in 0..code.width() {
            if code[(x, y)] == qrcode::Color::Dark {
                for dy in 0..8 {
                    let start = ((y + 4) * 8 + dy) * side + (x + 4) * 8;
                    pixels[start..start + 8].fill(0);
                }
            }
        }
    }
    let mut data = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut data, side as u32, side as u32);
        encoder.set_color(png::ColorType::Grayscale);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder.write_header()?;
        writer.write_image_data(&pixels)?;
    }
    private::save(output, &data)
}
pub fn poll_qr(state_path: &Path, grant_path: &Path) -> anyhow::Result<()> {
    anyhow::ensure!(
        state_path != grant_path,
        "Distinct state and grant paths required"
    );
    let saved: QrSession = serde_json::from_slice(&std::fs::read(state_path)?)?;
    let remaining = saved.expires_at - timestamp()?;
    anyhow::ensure!(
        saved.sid == "miconnect" && remaining > 0.0,
        "QR session expired"
    );
    let url = account_url(&saved.poll_url)?;
    let r = http::request(
        url.as_str(),
        None,
        &[("User-Agent", "Mozilla/5.0 MiClip")],
        remaining.min(50.0).ceil() as u32,
    )?;
    anyhow::ensure!(r.status == 200, "Account polling HTTP status {}", r.status);
    let grant = json_response(&r.body)?;
    check_code(&grant)?;
    for key in ["ssecurity", "location", "passToken"] {
        string(&grant, key)?;
    }
    private::save(grant_path, &serde_json::to_vec(&grant)?)
}
fn decimal(value: &Value) -> anyhow::Result<String> {
    match value {
        Value::Number(n) if n.is_i64() || n.is_u64() => Ok(n.to_string()),
        Value::String(s) if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) => Ok(s.clone()),
        _ => anyhow::bail!("Invalid account integer"),
    }
}
pub fn redeem_grant(grant_path: &Path, output: &Path) -> anyhow::Result<()> {
    anyhow::ensure!(
        grant_path != output,
        "Distinct grant and session paths required"
    );
    let grant = json_response(&std::fs::read(grant_path)?)?;
    check_code(&grant)?;
    let mut url = url::Url::parse(string(&grant, "location")?)
        .map_err(|_| anyhow::anyhow!("Invalid STS URL"))?;
    anyhow::ensure!(
        url.scheme() == "https"
            && url.host_str() == Some("sts-idm.api.io.mi.com")
            && url.path() == "/sts"
            && url.username().is_empty()
            && url.password().is_none()
            && url.port_or_known_default() == Some(443),
        "Unexpected STS URL"
    );
    let security = string(&grant, "ssecurity")?;
    let sign = STANDARD.encode(Sha1::digest(
        format!("nonce={}&{security}", decimal(&grant["nonce"])?).as_bytes(),
    ));
    url.query_pairs_mut().append_pair("clientSign", &sign);
    let r = http::request(
        url.as_str(),
        None,
        &[("User-Agent", "Mozilla/5.0 MiClip")],
        15,
    )?;
    anyhow::ensure!(r.status == 200, "STS HTTP status {}", r.status);
    let token = r
        .cookies()
        .into_iter()
        .find(|(name, _)| name == "serviceToken")
        .map(|(_, v)| v)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!("STS grant is expired, consumed, or rejected; no service token issued")
        })?;
    let session = Session {
        sid: "miconnect".into(),
        user_id: decimal(&grant["userId"])?,
        c_user_id: string(&grant, "cUserId")?.into(),
        ssecurity: security.into(),
        service_token: token,
    };
    private::save(output, &serde_json::to_vec(&session)?)
}
pub fn read_session(path: &Path) -> anyhow::Result<Session> {
    let session: Session = serde_json::from_slice(&std::fs::read(path)?)
        .map_err(|_| anyhow::anyhow!("Invalid private service session"))?;
    anyhow::ensure!(
        session.sid == "miconnect" && !session.user_id.is_empty(),
        "Unexpected service identity"
    );
    for value in [&session.service_token, &session.c_user_id] {
        anyhow::ensure!(
            !value.is_empty() && value.bytes().all(|b| b.is_ascii_graphic() && b != b';'),
            "Invalid private cookie value"
        );
    }
    Ok(session)
}
fn encode(value: &str) -> String {
    value
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}
pub fn signed_query(
    path: &str,
    plaintext: &[u8],
    security: &[u8],
    nonce: &[u8; 12],
    salt: &str,
    iv: &[u8; 12],
) -> anyhow::Result<(Vec<u8>, [u8; 32])> {
    let mut material = security.to_vec();
    material.extend(nonce);
    let key: [u8; 32] = Sha256::digest(material).into();
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|_| anyhow::anyhow!("Invalid request key"))?;
    let mut encrypted = iv.to_vec();
    encrypted.extend(
        cipher
            .encrypt(Nonce::from_slice(iv), plaintext)
            .map_err(|_| anyhow::anyhow!("Request encryption failed"))?,
    );
    let data = STANDARD.encode(encrypted);
    let input = [
        "POST",
        path,
        &format!("data={data}"),
        &format!("rc4_hash__={salt}"),
        &STANDARD.encode(key),
    ]
    .join("&");
    let signature = STANDARD.encode(Sha256::digest(input.as_bytes()));
    let mut fields = [
        ("_nonce", STANDARD.encode(nonce)),
        ("data", data),
        ("rc4_hash__", salt.into()),
        ("signature", signature),
    ];
    fields.sort_unstable_by_key(|(k, _)| *k);
    Ok((
        fields
            .into_iter()
            .map(|(k, v)| format!("{k}={}", encode(&v)))
            .collect::<Vec<_>>()
            .join("&")
            .into_bytes(),
        key,
    ))
}
fn api(session: &Session, path: &str, plaintext: &[u8]) -> anyhow::Result<Value> {
    let mut nonce: [u8; 12] = private::random()?;
    nonce[8..].copy_from_slice(&((timestamp()? / 60.0) as u32).to_be_bytes());
    let salt = URL_SAFE_NO_PAD.encode(private::random::<8>()?);
    let security = STANDARD
        .decode(&session.ssecurity)
        .map_err(|_| anyhow::anyhow!("Invalid private security encoding"))?;
    let (body, key) = signed_query(
        path,
        plaintext,
        &security,
        &nonce,
        &salt,
        &private::random()?,
    )?;
    let cookie = format!(
        "serviceToken={}; cUserId={}",
        session.service_token, session.c_user_id
    );
    let r = http::request(
        &format!("https://idm.api.io.mi.com/app{path}"),
        Some(&body),
        &[
            ("User-Agent", "IDM"),
            ("Content-Type", "application/x-www-form-urlencoded"),
            ("X-XIAOMI-PROTOCAL-FLAG", "PROTOCAL-HTTPS"),
            ("MIOT-ENCRYPT-ALGORITHM", "ENCRYPT-AES"),
            ("SHA-ALGORITHM", "HASH-SHA256"),
            ("Cookie", &cookie),
        ],
        20,
    )?;
    anyhow::ensure!(r.status == 200, "Certificate HTTP status {}", r.status);
    let plain = match STANDARD.decode(r.body.trim_ascii()) {
        Ok(data) if data.len() >= 28 => Aes256Gcm::new_from_slice(&key)
            .unwrap()
            .decrypt(Nonce::from_slice(&data[..12]), &data[12..])
            .map_err(|_| anyhow::anyhow!("Certificate response authentication failed"))?,
        _ => r.body,
    };
    let result = json_response(&plain)?;
    check_code(&result)?;
    Ok(result)
}
pub fn account_certificate(session: &Session, output: &Path) -> anyhow::Result<()> {
    let result = api(
        session,
        "/appgateway/miot/miconnect_server/MiconnectService/common/lv2Cert",
        b"{}\n",
    )?;
    private::save(output, string(&result["result"], "cert")?.as_bytes())
}
fn der(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if contents.len() < 128 {
        out.push(contents.len() as u8);
    } else {
        let n = contents.len().to_be_bytes();
        let start = n.iter().position(|&b| b != 0).unwrap();
        out.push(0x80 | (n.len() - start) as u8);
        out.extend(&n[start..]);
    }
    out.extend(contents);
    out
}
pub fn device_csr(identity: &DeviceIdentity, uid: &str) -> anyhow::Result<String> {
    let bytes = STANDARD.decode(&identity.private_key)?;
    let key = SigningKey::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("Invalid private signing key"))?;
    let account_hash =
        URL_SAFE_NO_PAD.encode(Sha256::digest(format!("{}{uid}", identity.did).as_bytes()));
    let cn = format!("lyra.{account_hash}.{}.14", identity.did);
    let mut attributes = vec![6, 3, 0x55, 4, 3];
    attributes.extend(der(0x0c, cn.as_bytes()));
    let subject = der(0x30, &der(0x31, &der(0x30, &attributes)));
    let mut info = vec![2, 1, 0];
    info.extend(subject);
    let public =
        p256::PublicKey::from_sec1_bytes(key.verifying_key().to_encoded_point(false).as_bytes())?;
    info.extend(public.to_public_key_der()?.as_bytes());
    info.extend([0xa0, 0]);
    let info = der(0x30, &info);
    let signature: Signature = key.sign(&info);
    let mut request = info;
    request.extend([0x30, 0x0a, 6, 8, 0x2a, 0x86, 0x48, 0xce, 0x3d, 4, 3, 2]);
    let mut bits = vec![0];
    bits.extend(signature.to_der().as_bytes());
    request.extend(der(3, &bits));
    let encoded = STANDARD.encode(der(0x30, &request));
    Ok(format!(
        "-----BEGIN CERTIFICATE REQUEST-----\n{}\n-----END CERTIFICATE REQUEST-----\n",
        encoded
            .as_bytes()
            .chunks(64)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join("\n")
    ))
}
pub fn device_certificate(session: &Session, directory: &Path) -> anyhow::Result<()> {
    let path = directory.join("device.json");
    let identity: DeviceIdentity = if path.exists() {
        serde_json::from_slice(&std::fs::read(&path)?)?
    } else {
        let key = SigningKey::from_slice(&private::random::<32>()?)
            .map_err(|_| anyhow::anyhow!("Device key generation failed"))?;
        let identity = DeviceIdentity {
            private_key: STANDARD.encode(key.to_bytes()),
            did: URL_SAFE_NO_PAD.encode(private::random::<4>()?),
        };
        private::save(&path, &serde_json::to_vec(&identity)?)?;
        identity
    };
    let csr = device_csr(&identity, &session.user_id)?;
    private::save(&directory.join("device.csr"), csr.as_bytes())?;
    let mut body = serde_json::to_vec(
        &json!({"did":identity.did,"deviceType":14,"csr":csr,"uniDid":"","preDid":"","preUid":0}),
    )?;
    body.push(b'\n');
    let result = api(
        session,
        "/appgateway/miot/miconnect_server/MiconnectService/common/lyra/getCert",
        &body,
    )?;
    private::save(
        &directory.join("device-cert.pem"),
        string(&result["result"], "cert")?.as_bytes(),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn authorization_boundaries_and_exact_integers() {
        for bad in [
            "http://account.xiaomi.com/",
            "https://account.xiaomi.com.evil.test/",
            "https://account.xiaomi.com@evil.test/",
            "https://account.xiaomi.com:444/",
        ] {
            assert!(account_url(bad).is_err());
        }
        assert!(account_url("https://ak.lp.account.xiaomi.com/lp/s?k=synthetic").is_ok());
        let value = json_response(b"&&&START&&&{\"nonce\":18446744073709551615}").unwrap();
        assert_eq!(decimal(&value["nonce"]).unwrap(), "18446744073709551615");
    }
    #[test]
    fn gcm_vector_and_tamper_rejection() {
        let cipher = Aes256Gcm::new_from_slice(&[0; 32]).unwrap();
        let encrypted = cipher
            .encrypt(Nonce::from_slice(&[0; 12]), &[0; 16][..])
            .unwrap();
        assert_eq!(
            encrypted
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
            "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919"
        );
        let mut corrupt = encrypted;
        corrupt[0] ^= 1;
        assert!(
            cipher
                .decrypt(Nonce::from_slice(&[0; 12]), corrupt.as_slice())
                .is_err()
        );
    }
}
