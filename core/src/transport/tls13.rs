//! Собственный TLS 1.3-клиент (ClientHello в стиле Chrome) для REALITY и для
//! обычного TLS там, где нужен доступ к записям (XTLS Vision).
//!
//! Схема (как в Xray-core `transport/internet/reality`):
//! * session_id = [ver_x, ver_y, ver_z, 0, unix_time(4), short_id(8), ...] шифруется
//!   AES-GCM ключом auth_key = HKDF-SHA256(X25519(eph, server_pub), salt=random[..20], "REALITY"),
//!   nonce = random[20..], AAD = ClientHello с обнулённым session_id;
//! * сервер REALITY отвечает временным ed25519-сертификатом, подпись которого
//!   равна HMAC-SHA512(auth_key, публичный ключ) — так клиент убеждается, что
//!   говорит с настоящим сервером, а не с сайтом-маской.
//!
//! После рукопожатия соединение делится на независимые половины чтения/записи,
//! что нужно для XTLS Vision (переключение на "сырой" TCP).

use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::Aes256Gcm;
use base64::Engine;
use hmac::{Hmac, Mac};
use rand::seq::SliceRandom;
use rand::Rng;
use sha2::{Sha256, Sha512};
use tokio::io::AsyncWriteExt;
use x25519_dalek::{PublicKey, StaticSecret};

use super::secure::{HashAlg, RecordCipher, RecordKind, SecureConn, SecureReader, SecureWriter};
use crate::common::{io_err, BoxStream};

const VERSION: [u8; 3] = [26, 3, 27];

#[derive(Clone, Debug)]
pub struct RealityConfig {
    pub server_name: String,
    pub public_key: [u8; 32],
    pub short_id: [u8; 8],
    pub alpn: Vec<String>,
}

impl RealityConfig {
    pub fn new(server_name: &str, public_key: &str, short_id: &str, alpn: &str) -> io::Result<Self> {
        let pk = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(public_key.trim().trim_end_matches('='))
            .or_else(|_| base64::engine::general_purpose::STANDARD.decode(public_key.trim()))
            .map_err(|_| io_err("REALITY: неверный publicKey (pbk)"))?;
        let public_key: [u8; 32] = pk.try_into().map_err(|_| io_err("REALITY: publicKey должен быть 32 байта"))?;
        let sid = short_id.trim();
        if sid.len() > 16 || sid.len() % 2 != 0 {
            return Err(io_err("REALITY: неверный shortId"));
        }
        let mut short = [0u8; 8];
        for i in 0..sid.len() / 2 {
            short[i] = u8::from_str_radix(&sid[i * 2..i * 2 + 2], 16).map_err(|_| io_err("REALITY: неверный shortId"))?;
        }
        let alpn = alpn.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
        Ok(Self { server_name: server_name.to_string(), public_key, short_id: short, alpn })
    }
}

// ───────────────────────── ClientHello ─────────────────────────

fn grease() -> u16 {
    let v: u8 = rand::thread_rng().gen_range(0..16);
    let b = (v << 4) | 0x0a;
    u16::from_be_bytes([b, b])
}

fn put_u16(v: &mut Vec<u8>, x: u16) {
    v.extend_from_slice(&x.to_be_bytes());
}

fn ext(out: &mut Vec<u8>, typ: u16, body: &[u8]) {
    put_u16(out, typ);
    put_u16(out, body.len() as u16);
    out.extend_from_slice(body);
}

/// Собирает тело ClientHello (без заголовка handshake), похожее на Chrome.
fn build_client_hello(random: &[u8; 32], key_share: &[u8; 32], sni: &str, alpn: &[String]) -> Vec<u8> {
    let g_cipher = grease();
    let g_ext1 = grease();
    let mut g_ext2 = grease();
    while g_ext2 == g_ext1 {
        g_ext2 = grease();
    }
    let g_group = grease();
    let g_ver = grease();

    let mut b = Vec::with_capacity(512);
    b.extend_from_slice(&[0x03, 0x03]);
    b.extend_from_slice(random);
    b.push(32);
    b.extend_from_slice(&[0u8; 32]); // session_id — заполняется позже
    let suites: [u16; 16] = [
        g_cipher, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d,
        0x002f, 0x0035,
    ];
    put_u16(&mut b, (suites.len() * 2) as u16);
    for s in suites {
        put_u16(&mut b, s);
    }
    b.extend_from_slice(&[0x01, 0x00]);

    // Расширения: как у Chrome, порядок перемешивается (кроме GREASE в начале/конце).
    let mut exts: Vec<Vec<u8>> = Vec::new();
    let mut e = Vec::new();
    // server_name
    if !sni.is_empty() && sni.parse::<std::net::IpAddr>().is_err() {
        let mut body = Vec::new();
        put_u16(&mut body, (sni.len() + 3) as u16);
        body.push(0);
        put_u16(&mut body, sni.len() as u16);
        body.extend_from_slice(sni.as_bytes());
        ext(&mut e, 0x0000, &body);
        exts.push(std::mem::take(&mut e));
    }
    ext(&mut e, 0x0017, &[]); // extended_master_secret
    exts.push(std::mem::take(&mut e));
    ext(&mut e, 0xff01, &[0x00]); // renegotiation_info
    exts.push(std::mem::take(&mut e));
    {
        let mut body = Vec::new();
        let groups = [g_group, 0x001d, 0x0017, 0x0018];
        put_u16(&mut body, (groups.len() * 2) as u16);
        for gr in groups {
            put_u16(&mut body, gr);
        }
        ext(&mut e, 0x000a, &body); // supported_groups
        exts.push(std::mem::take(&mut e));
    }
    ext(&mut e, 0x000b, &[0x01, 0x00]); // ec_point_formats
    exts.push(std::mem::take(&mut e));
    ext(&mut e, 0x0023, &[]); // session_ticket
    exts.push(std::mem::take(&mut e));
    {
        let protos: Vec<String> =
            if alpn.is_empty() { vec!["h2".into(), "http/1.1".into()] } else { alpn.to_vec() };
        let mut list = Vec::new();
        for p in &protos {
            list.push(p.len() as u8);
            list.extend_from_slice(p.as_bytes());
        }
        let mut body = Vec::new();
        put_u16(&mut body, list.len() as u16);
        body.extend_from_slice(&list);
        ext(&mut e, 0x0010, &body); // ALPN
        exts.push(std::mem::take(&mut e));
    }
    ext(&mut e, 0x0005, &[0x01, 0x00, 0x00, 0x00, 0x00]); // status_request
    exts.push(std::mem::take(&mut e));
    {
        let algs: [u16; 8] = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601];
        let mut body = Vec::new();
        put_u16(&mut body, 16);
        for a in algs {
            put_u16(&mut body, a);
        }
        ext(&mut e, 0x000d, &body); // signature_algorithms
        exts.push(std::mem::take(&mut e));
    }
    ext(&mut e, 0x0012, &[]); // signed_certificate_timestamp
    exts.push(std::mem::take(&mut e));
    {
        let mut shares = Vec::new();
        put_u16(&mut shares, g_group);
        put_u16(&mut shares, 1);
        shares.push(0);
        put_u16(&mut shares, 0x001d);
        put_u16(&mut shares, 32);
        shares.extend_from_slice(key_share);
        let mut body = Vec::new();
        put_u16(&mut body, shares.len() as u16);
        body.extend_from_slice(&shares);
        ext(&mut e, 0x0033, &body); // key_share
        exts.push(std::mem::take(&mut e));
    }
    ext(&mut e, 0x002d, &[0x01, 0x01]); // psk_key_exchange_modes
    exts.push(std::mem::take(&mut e));
    {
        let mut body = vec![6];
        put_u16(&mut body, g_ver);
        put_u16(&mut body, 0x0304);
        put_u16(&mut body, 0x0303);
        ext(&mut e, 0x002b, &body); // supported_versions
        exts.push(std::mem::take(&mut e));
    }
    exts.shuffle(&mut rand::thread_rng());

    let mut all = Vec::new();
    ext(&mut all, g_ext1, &[]);
    for x in exts {
        all.extend_from_slice(&x);
    }
    ext(&mut all, g_ext2, &[0x00]);
    // padding (BoringSSL): довести ClientHello до 512 байт
    let unpadded = b.len() + 2 + all.len() + 4;
    if unpadded > 0xff && unpadded < 0x200 {
        let mut pad = 0x200 - unpadded;
        pad = pad.saturating_sub(4).max(1);
        ext(&mut all, 0x0015, &vec![0u8; pad]);
    }
    put_u16(&mut b, all.len() as u16);
    b.extend_from_slice(&all);
    b
}

// ───────────────────────── рукопожатие ─────────────────────────

struct HsReader<'a> {
    reader: &'a mut SecureReader,
    buf: Vec<u8>,
}

impl HsReader<'_> {
    /// Возвращает следующее handshake-сообщение целиком (с 4-байтным заголовком).
    async fn next_msg(&mut self, encrypted: bool) -> io::Result<Vec<u8>> {
        loop {
            if self.buf.len() >= 4 {
                let len = ((self.buf[1] as usize) << 16) | ((self.buf[2] as usize) << 8) | self.buf[3] as usize;
                if self.buf.len() >= 4 + len {
                    let msg = self.buf[..4 + len].to_vec();
                    self.buf.drain(..4 + len);
                    return Ok(msg);
                }
            }
            let Some((typ, header, mut body)) = self.reader.read_raw_record().await? else {
                return Err(io_err("REALITY: сервер закрыл соединение во время рукопожатия"));
            };
            match typ {
                0x14 => continue,
                0x15 => return Err(io_err(format!("REALITY: сервер прислал alert {:?}", body))),
                0x16 if !encrypted => self.buf.extend_from_slice(&body),
                0x17 if encrypted => {
                    let inner = self.reader.cipher.open(&header, &mut body)?;
                    match inner {
                        0x16 => self.buf.extend_from_slice(&body),
                        0x15 => return Err(io_err("REALITY: alert во время рукопожатия")),
                        _ => return Err(io_err("REALITY: неожиданные данные во время рукопожатия")),
                    }
                }
                _ => return Err(io_err(format!("REALITY: неожиданная запись {typ:#x}"))),
            }
        }
    }
}

fn parse_server_hello(msg: &[u8]) -> io::Result<(u16, [u8; 32])> {
    let err = || io_err("REALITY: некорректный ServerHello");
    if msg.first() != Some(&0x02) {
        return Err(err());
    }
    let b = &msg[4..];
    if b.len() < 38 {
        return Err(err());
    }
    let random = &b[2..34];
    const HRR: [u8; 32] = [
        0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91, 0xC2, 0xA2, 0x11, 0x16,
        0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
    ];
    if random == HRR {
        return Err(io_err("REALITY: сервер запросил HelloRetryRequest (неподдерживаемая группа)"));
    }
    let sid_len = b[34] as usize;
    let mut p = 35 + sid_len;
    let suite = u16::from_be_bytes([*b.get(p).ok_or_else(err)?, *b.get(p + 1).ok_or_else(err)?]);
    p += 3; // suite + compression
    let ext_len = u16::from_be_bytes([*b.get(p).ok_or_else(err)?, *b.get(p + 1).ok_or_else(err)?]) as usize;
    p += 2;
    let end = (p + ext_len).min(b.len());
    let mut key = None;
    let mut tls13 = false;
    while p + 4 <= end {
        let t = u16::from_be_bytes([b[p], b[p + 1]]);
        let l = u16::from_be_bytes([b[p + 2], b[p + 3]]) as usize;
        let body = b.get(p + 4..p + 4 + l).ok_or_else(err)?;
        match t {
            0x002b => tls13 = body == [0x03, 0x04],
            0x0033 => {
                if body.len() >= 4 && u16::from_be_bytes([body[0], body[1]]) == 0x001d && body.len() >= 36 {
                    let mut k = [0u8; 32];
                    k.copy_from_slice(&body[4..36]);
                    key = Some(k);
                }
            }
            _ => {}
        }
        p += 4 + l;
    }
    if !tls13 {
        return Err(io_err("REALITY: сервер не согласовал TLS 1.3"));
    }
    if !matches!(suite, 0x1301 | 0x1302 | 0x1303) {
        return Err(io_err("REALITY: неподдерживаемый cipher suite"));
    }
    Ok((suite, key.ok_or_else(|| io_err("REALITY: нет key_share X25519 в ServerHello"))?))
}

/// Извлекает (ed25519 pubkey, signature) из DER-сертификата.
fn cert_ed25519(der: &[u8]) -> Option<([u8; 32], Vec<u8>)> {
    const OID: [u8; 5] = [0x06, 0x03, 0x2b, 0x65, 0x70];
    let pos = der.windows(5).position(|w| w == OID)?;
    let rest = &der[pos + 5..];
    let bs = rest.windows(3).position(|w| w == [0x03, 0x21, 0x00])?;
    let pk: [u8; 32] = rest.get(bs + 3..bs + 35)?.try_into().ok()?;
    // signatureValue — последний BIT STRING сертификата (03 41 00 + 64 байта)
    if der.len() < 67 || der[der.len() - 67..der.len() - 64] != [0x03, 0x41, 0x00] {
        return None;
    }
    Some((pk, der[der.len() - 64..].to_vec()))
}


/// Режим рукопожатия.
pub enum Mode<'a> {
    Reality(&'a RealityConfig),
    /// Обычный TLS 1.3 с проверкой сертификата (или без неё)
    Verify { insecure: bool },
}

fn cert_list(msg: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let b = &msg[4..];
    let Some(&ctx) = b.first() else { return out };
    let mut p = 1 + ctx as usize + 3;
    while p + 3 <= b.len() {
        let l = ((b[p] as usize) << 16) | ((b[p + 1] as usize) << 8) | b[p + 2] as usize;
        let Some(c) = b.get(p + 3..p + 3 + l) else { break };
        out.push(c.to_vec());
        p += 3 + l;
        if p + 2 > b.len() {
            break;
        }
        let el = u16::from_be_bytes([b[p], b[p + 1]]) as usize;
        p += 2 + el;
    }
    out
}

fn verify_chain(chain: &[Vec<u8>], sni: &str) -> io::Result<()> {
    use rustls::client::danger::ServerCertVerifier;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use std::sync::OnceLock;
    static VERIFIER: OnceLock<std::sync::Arc<rustls::client::WebPkiServerVerifier>> = OnceLock::new();
    let v = VERIFIER.get_or_init(|| {
        let mut roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
        // дополнительный корневой сертификат (PEM), напр. для собственного CA
        if let Ok(path) = std::env::var("XD_EXTRA_CA") {
            if let Ok(pem) = std::fs::read_to_string(path) {
                for block in pem.split("-----BEGIN CERTIFICATE-----").skip(1) {
                    let b64: String = block.split("-----END").next().unwrap_or("").chars().filter(|c| !c.is_whitespace()).collect();
                    if let Ok(der) = base64::engine::general_purpose::STANDARD.decode(b64) {
                        let _ = roots.add(rustls::pki_types::CertificateDer::from(der));
                    }
                }
            }
        }
        rustls::client::WebPkiServerVerifier::builder_with_provider(
            std::sync::Arc::new(roots),
            std::sync::Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .expect("verifier")
    });
    let ee = CertificateDer::from(chain.first().ok_or_else(|| io_err("TLS: сервер не прислал сертификат"))?.clone());
    let inter: Vec<CertificateDer> = chain[1..].iter().map(|c| CertificateDer::from(c.clone())).collect();
    let name = ServerName::try_from(sni.to_string()).map_err(|_| io_err("TLS: неверное имя сервера"))?;
    v.verify_server_cert(&ee, &inter, &name, &[], UnixTime::now())
        .map(|_| ())
        .map_err(|e| io_err(format!("TLS: сертификат не прошёл проверку: {e}")))
}

fn verify_cert_verify(cert: &[u8], msg: &[u8], transcript_hash: &[u8]) -> io::Result<()> {
    use webpki::ring as alg;
    let b = &msg[4..];
    if b.len() < 4 {
        return Err(io_err("TLS: неверный CertificateVerify"));
    }
    let scheme = u16::from_be_bytes([b[0], b[1]]);
    let l = u16::from_be_bytes([b[2], b[3]]) as usize;
    let sig = b.get(4..4 + l).ok_or_else(|| io_err("TLS: неверный CertificateVerify"))?;
    let mut signed = vec![0x20u8; 64];
    signed.extend_from_slice(b"TLS 1.3, server CertificateVerify\0");
    signed.extend_from_slice(transcript_hash);
    let algorithm: &dyn rustls::pki_types::SignatureVerificationAlgorithm = match scheme {
        0x0403 => alg::ECDSA_P256_SHA256,
        0x0503 => alg::ECDSA_P384_SHA384,
        0x0804 => alg::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
        0x0805 => alg::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
        0x0806 => alg::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
        0x0807 => alg::ED25519,
        _ => return Err(io_err(format!("TLS: неподдерживаемая подпись {scheme:#06x}"))),
    };
    let der = rustls::pki_types::CertificateDer::from(cert.to_vec());
    let ee = webpki::EndEntityCert::try_from(&der).map_err(|e| io_err(format!("TLS: {e}")))?;
    ee.verify_signature(algorithm, &signed, sig).map_err(|_| io_err("TLS: неверная подпись CertificateVerify"))
}

/// TLS 1.3-рукопожатие поверх произвольного потока.
pub async fn handshake(io: BoxStream, sni: &str, alpn: &[String], mode: Mode<'_>) -> io::Result<SecureConn> {
    let (rd, mut wr) = super::secure::split(io);

    let eph = StaticSecret::random_from_rng(rand::thread_rng());
    let eph_pub = PublicKey::from(&eph);
    let mut random = [0u8; 32];
    crate::common::random_bytes(&mut random);

    let body = build_client_hello(&random, eph_pub.as_bytes(), sni, alpn);
    let mut hello = Vec::with_capacity(body.len() + 4);
    hello.push(0x01);
    hello.extend_from_slice(&[(body.len() >> 16) as u8, (body.len() >> 8) as u8, body.len() as u8]);
    hello.extend_from_slice(&body);

    let mut sid = [0u8; 32];
    let mut auth_key = [0u8; 32];
    match &mode {
        Mode::Reality(cfg) => {
            sid[0] = VERSION[0];
            sid[1] = VERSION[1];
            sid[2] = VERSION[2];
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32;
            sid[4..8].copy_from_slice(&now.to_be_bytes());
            sid[8..16].copy_from_slice(&cfg.short_id);
            let shared = eph.diffie_hellman(&PublicKey::from(cfg.public_key));
            hkdf::Hkdf::<Sha256>::new(Some(&random[..20]), shared.as_bytes())
                .expand(b"REALITY", &mut auth_key)
                .unwrap();
            let aead = Aes256Gcm::new_from_slice(&auth_key).unwrap();
            let nonce = aes_gcm::Nonce::from_slice(&random[20..32]);
            let mut pt = sid[..16].to_vec();
            let tag = aead.encrypt_in_place_detached(nonce, &hello, &mut pt).map_err(|_| io_err("seal"))?;
            sid[..16].copy_from_slice(&pt);
            sid[16..].copy_from_slice(&tag);
        }
        Mode::Verify { .. } => crate::common::random_bytes(&mut sid),
    }
    hello[39..71].copy_from_slice(&sid);

    let mut rec = vec![0x16, 0x03, 0x01, (hello.len() >> 8) as u8, hello.len() as u8];
    rec.extend_from_slice(&hello);
    wr.write_all(&rec).await?;

    let mut transcript = hello.clone();
    let dummy = RecordCipher::new(0x1301, HashAlg::Sha256, &[0u8; 32]);
    let mut reader = SecureReader::new(rd, dummy, RecordKind::Tls13);

    let mut hs = HsReader { reader: &mut reader, buf: Vec::new() };
    let sh = hs.next_msg(false).await?;
    let (suite, server_key) = parse_server_hello(&sh)?;
    transcript.extend_from_slice(&sh);
    let hash = if suite == 0x1302 { HashAlg::Sha384 } else { HashAlg::Sha256 };
    let hl = hash.len();

    let ecdhe = eph.diffie_hellman(&PublicKey::from(server_key));
    let early = hash.extract(&[], &vec![0u8; hl]);
    let derived = hash.expand_label(&early, "derived", &hash.hash(&[]), hl);
    let hs_secret = hash.extract(&derived, ecdhe.as_bytes());
    let th = hash.hash(&transcript);
    let c_hs = hash.expand_label(&hs_secret, "c hs traffic", &th, hl);
    let s_hs = hash.expand_label(&hs_secret, "s hs traffic", &th, hl);
    hs.reader.cipher = RecordCipher::new(suite, hash, &s_hs);
    if !hs.buf.is_empty() {
        return Err(io_err("TLS: лишние данные после ServerHello"));
    }

    let mut reality_ok = false;
    let mut chain: Vec<Vec<u8>> = Vec::new();
    loop {
        let msg = hs.next_msg(true).await?;
        match msg[0] {
            8 => transcript.extend_from_slice(&msg),
            11 => {
                chain = cert_list(&msg);
                if let Mode::Reality(_) = mode {
                    if let Some((pk, sig)) = chain.first().and_then(|c| cert_ed25519(c)) {
                        let mut m = <Hmac<Sha512> as Mac>::new_from_slice(&auth_key).unwrap();
                        m.update(&pk);
                        if m.finalize().into_bytes().as_slice() == sig.as_slice() {
                            reality_ok = true;
                        }
                    }
                }
                transcript.extend_from_slice(&msg);
            }
            15 => {
                if let Mode::Verify { insecure: false } = mode {
                    verify_chain(&chain, sni)?;
                    verify_cert_verify(&chain[0], &msg, &hash.hash(&transcript))?;
                }
                transcript.extend_from_slice(&msg);
            }
            20 => {
                let fk = hash.expand_label(&s_hs, "finished", &[], hl);
                let expect = hash.hmac(&fk, &hash.hash(&transcript));
                if msg[4..] != expect[..] {
                    return Err(io_err("TLS: неверный Finished сервера"));
                }
                transcript.extend_from_slice(&msg);
                break;
            }
            13 => return Err(io_err("TLS: сервер запросил клиентский сертификат")),
            t => return Err(io_err(format!("TLS: неожиданное сообщение {t}"))),
        }
    }
    if let Mode::Reality(_) = mode {
        if !reality_ok {
            return Err(io_err(
                "REALITY: проверка не пройдена — сервер ответил как обычный сайт (неверные pbk/sid/sni или рассинхрон времени)",
            ));
        }
    }

    let th_fin = hash.hash(&transcript);
    let derived2 = hash.expand_label(&hs_secret, "derived", &hash.hash(&[]), hl);
    let master = hash.extract(&derived2, &vec![0u8; hl]);
    let c_ap = hash.expand_label(&master, "c ap traffic", &th_fin, hl);
    let s_ap = hash.expand_label(&master, "s ap traffic", &th_fin, hl);

    let fk = hash.expand_label(&c_hs, "finished", &[], hl);
    let verify = hash.hmac(&fk, &th_fin);
    let mut fin = vec![20, 0, 0, hl as u8];
    fin.extend_from_slice(&verify);
    let mut c_hs_cipher = RecordCipher::new(suite, hash, &c_hs);
    let mut out = vec![0x14, 0x03, 0x03, 0x00, 0x01, 0x01];
    out.extend_from_slice(&c_hs_cipher.seal(0x16, &fin));
    wr.write_all(&out).await?;

    reader.cipher = RecordCipher::new(suite, hash, &s_ap);
    let writer = SecureWriter::new(wr, RecordCipher::new(suite, hash, &c_ap), RecordKind::Tls13);
    Ok(SecureConn { reader, writer })
}

#[cfg(test)]
mod tests {
    use super::*;

    use super::super::secure::HashAlg;

    #[test]
    fn hkdf_label_rfc8448() {
        // RFC 8448: derived secret из early secret без PSK
        let h = HashAlg::Sha256;
        let early = h.extract(&[], &[0u8; 32]);
        assert_eq!(hex(&early), "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a");
        let derived = h.expand_label(&early, "derived", &h.hash(&[]), 32);
        assert_eq!(hex(&derived), "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba");
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn hello_len() {
        let h = build_client_hello(&[1u8; 32], &[2u8; 32], "www.example.com", &[]);
        assert!(h.len() + 4 >= 512, "len {}", h.len());
    }
}
