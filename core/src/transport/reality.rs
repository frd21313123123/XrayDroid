//! Клиент REALITY: минимальная реализация TLS 1.3 с ClientHello в стиле Chrome.
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
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use base64::Engine;
use chacha20poly1305::ChaCha20Poly1305;
use hmac::{Hmac, Mac};
use rand::seq::SliceRandom;
use rand::Rng;
use sha2::{Digest, Sha256, Sha384, Sha512};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::common::{io_err, BoxStream};

const VERSION: [u8; 3] = [26, 3, 27];
const MAX_PLAINTEXT: usize = 16384;

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

// ───────────────────────── криптопримитивы TLS 1.3 ─────────────────────────

#[derive(Clone, Copy, PartialEq, Debug)]
enum HashAlg {
    Sha256,
    Sha384,
}

impl HashAlg {
    fn len(self) -> usize {
        match self {
            HashAlg::Sha256 => 32,
            HashAlg::Sha384 => 48,
        }
    }
    fn hash(self, data: &[u8]) -> Vec<u8> {
        match self {
            HashAlg::Sha256 => Sha256::digest(data).to_vec(),
            HashAlg::Sha384 => Sha384::digest(data).to_vec(),
        }
    }
    fn hmac(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        match self {
            HashAlg::Sha256 => {
                let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).unwrap();
                m.update(data);
                m.finalize().into_bytes().to_vec()
            }
            HashAlg::Sha384 => {
                let mut m = <Hmac<Sha384> as Mac>::new_from_slice(key).unwrap();
                m.update(data);
                m.finalize().into_bytes().to_vec()
            }
        }
    }
    fn extract(self, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        let zero = vec![0u8; self.len()];
        let salt = if salt.is_empty() { &zero[..] } else { salt };
        self.hmac(salt, ikm)
    }
    fn expand(self, prk: &[u8], info: &[u8], len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        let mut t: Vec<u8> = Vec::new();
        let mut i = 1u8;
        while out.len() < len {
            let mut d = t.clone();
            d.extend_from_slice(info);
            d.push(i);
            t = self.hmac(prk, &d);
            out.extend_from_slice(&t);
            i += 1;
        }
        out.truncate(len);
        out
    }
    fn expand_label(self, secret: &[u8], label: &str, ctx: &[u8], len: usize) -> Vec<u8> {
        let full = format!("tls13 {label}");
        let mut info = Vec::new();
        info.extend_from_slice(&(len as u16).to_be_bytes());
        info.push(full.len() as u8);
        info.extend_from_slice(full.as_bytes());
        info.push(ctx.len() as u8);
        info.extend_from_slice(ctx);
        self.expand(secret, &info, len)
    }
}

enum Aead {
    A128(Box<Aes128Gcm>),
    A256(Box<Aes256Gcm>),
    Chacha(Box<ChaCha20Poly1305>),
}

pub(crate) struct RecordCipher {
    aead: Aead,
    iv: [u8; 12],
    seq: u64,
}

impl RecordCipher {
    fn new(suite: u16, hash: HashAlg, secret: &[u8]) -> Self {
        let key_len = if suite == 0x1301 { 16 } else { 32 };
        let key = hash.expand_label(secret, "key", &[], key_len);
        let ivv = hash.expand_label(secret, "iv", &[], 12);
        let aead = match suite {
            0x1301 => Aead::A128(Box::new(Aes128Gcm::new_from_slice(&key).unwrap())),
            0x1302 => Aead::A256(Box::new(Aes256Gcm::new_from_slice(&key).unwrap())),
            _ => Aead::Chacha(Box::new(ChaCha20Poly1305::new_from_slice(&key).unwrap())),
        };
        let mut iv = [0u8; 12];
        iv.copy_from_slice(&ivv);
        Self { aead, iv, seq: 0 }
    }

    fn nonce(&self) -> [u8; 12] {
        let mut n = self.iv;
        let s = self.seq.to_be_bytes();
        for i in 0..8 {
            n[4 + i] ^= s[i];
        }
        n
    }

    /// Шифрует plaintext||type и возвращает готовую TLS-запись.
    fn seal(&mut self, content_type: u8, data: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(5 + data.len() + 1 + 16);
        let len = data.len() + 1 + 16;
        buf.extend_from_slice(&[0x17, 0x03, 0x03, (len >> 8) as u8, len as u8]);
        let header: [u8; 5] = buf[..5].try_into().unwrap();
        let mut body = Vec::with_capacity(len);
        body.extend_from_slice(data);
        body.push(content_type);
        let nonce = self.nonce();
        let n = aes_gcm::Nonce::from_slice(&nonce);
        let tag = match &self.aead {
            Aead::A128(c) => c.encrypt_in_place_detached(n, &header, &mut body),
            Aead::A256(c) => c.encrypt_in_place_detached(n, &header, &mut body),
            Aead::Chacha(c) => c.encrypt_in_place_detached(n, &header, &mut body),
        }
        .expect("encrypt");
        self.seq += 1;
        buf.extend_from_slice(&body);
        buf.extend_from_slice(&tag);
        buf
    }

    /// Расшифровывает запись; возвращает (тип содержимого, данные).
    fn open(&mut self, header: &[u8; 5], payload: &mut Vec<u8>) -> io::Result<u8> {
        if payload.len() < 17 {
            return Err(io_err("TLS: слишком короткая запись"));
        }
        let tag_pos = payload.len() - 16;
        let tag = aes_gcm::Tag::clone_from_slice(&payload[tag_pos..]);
        payload.truncate(tag_pos);
        let nonce = self.nonce();
        let n = aes_gcm::Nonce::from_slice(&nonce);
        match &self.aead {
            Aead::A128(c) => c.decrypt_in_place_detached(n, header, payload, &tag),
            Aead::A256(c) => c.decrypt_in_place_detached(n, header, payload, &tag),
            Aead::Chacha(c) => c.decrypt_in_place_detached(n, header, payload, &tag),
        }
        .map_err(|_| io_err("TLS: ошибка расшифровки записи (bad_record_mac)"))?;
        self.seq += 1;
        while let Some(&0) = payload.last() {
            payload.pop();
        }
        payload.pop().ok_or_else(|| io_err("TLS: пустая запись"))
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

// ───────────────────────── чтение записей ─────────────────────────

/// Половина соединения для чтения: буферизует сырые байты TCP.
pub struct TlsReader {
    rd: OwnedReadHalf,
    raw: Vec<u8>,
    cipher: RecordCipher,
}

impl TlsReader {
    async fn fill(&mut self, need: usize) -> io::Result<bool> {
        while self.raw.len() < need {
            let mut tmp = [0u8; 16 * 1024];
            let n = self.rd.read(&mut tmp).await?;
            if n == 0 {
                return Ok(false);
            }
            self.raw.extend_from_slice(&tmp[..n]);
        }
        Ok(true)
    }

    /// Читает одну сырую запись: (тип, заголовок, тело).
    async fn read_raw_record(&mut self) -> io::Result<Option<(u8, [u8; 5], Vec<u8>)>> {
        if !self.fill(5).await? {
            return Ok(None);
        }
        let header: [u8; 5] = self.raw[..5].try_into().unwrap();
        let len = u16::from_be_bytes([header[3], header[4]]) as usize;
        if len > MAX_PLAINTEXT + 2048 {
            return Err(io_err("TLS: запись слишком большая"));
        }
        if !self.fill(5 + len).await? {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "TLS: обрыв записи"));
        }
        let body = self.raw[5..5 + len].to_vec();
        self.raw.drain(..5 + len);
        Ok(Some((header[0], header, body)))
    }

    /// Читает очередную порцию данных приложения. None — конец потока.
    pub async fn read_app(&mut self) -> io::Result<Option<Vec<u8>>> {
        loop {
            let Some((typ, header, mut body)) = self.read_raw_record().await? else {
                return Ok(None);
            };
            match typ {
                0x14 => continue, // change_cipher_spec
                0x17 => {
                    let inner = self.cipher.open(&header, &mut body)?;
                    match inner {
                        0x17 => {
                            if body.is_empty() {
                                continue;
                            }
                            return Ok(Some(body));
                        }
                        0x16 => continue, // NewSessionTicket и т.п.
                        0x15 => return Ok(None), // alert (close_notify)
                        _ => return Err(io_err("TLS: неизвестный тип записи")),
                    }
                }
                0x15 => return Ok(None),
                _ => return Err(io_err(format!("TLS: неожиданная запись {typ:#x}"))),
            }
        }
    }

    /// Забирает сырые, ещё не расшифрованные байты (для перехода Vision в direct).
    pub fn take_raw(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.raw)
    }

    /// Прямое чтение из TCP (после перехода в direct).
    pub async fn read_raw(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if !self.raw.is_empty() {
            let n = self.raw.len().min(buf.len());
            buf[..n].copy_from_slice(&self.raw[..n]);
            self.raw.drain(..n);
            return Ok(n);
        }
        self.rd.read(buf).await
    }
}

/// Половина соединения для записи.
pub struct TlsWriter {
    wr: OwnedWriteHalf,
    cipher: RecordCipher,
}

impl TlsWriter {
    pub async fn write_app(&mut self, data: &[u8]) -> io::Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        let mut out = Vec::with_capacity(data.len() + 64);
        for chunk in data.chunks(MAX_PLAINTEXT) {
            out.extend_from_slice(&self.cipher.seal(0x17, chunk));
        }
        self.wr.write_all(&out).await
    }

    pub async fn write_raw(&mut self, data: &[u8]) -> io::Result<()> {
        self.wr.write_all(data).await
    }

    pub async fn close(&mut self) {
        let rec = self.cipher.seal(0x15, &[0x01, 0x00]);
        let _ = self.wr.write_all(&rec).await;
        let _ = self.wr.shutdown().await;
    }

    pub async fn shutdown_raw(&mut self) {
        let _ = self.wr.shutdown().await;
    }
}

pub struct RealityConn {
    pub reader: TlsReader,
    pub writer: TlsWriter,
}

impl RealityConn {
    /// Превращает соединение в обычный поток (через внутренний канал).
    pub fn into_stream(self) -> BoxStream {
        let (a, b) = tokio::io::duplex(128 * 1024);
        let (mut br, mut bw) = tokio::io::split(b);
        let RealityConn { mut reader, mut writer } = self;
        tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_PLAINTEXT];
            loop {
                match br.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if writer.write_app(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
            writer.close().await;
        });
        tokio::spawn(async move {
            while let Ok(Some(d)) = reader.read_app().await {
                if bw.write_all(&d).await.is_err() {
                    break;
                }
            }
            let _ = bw.shutdown().await;
        });
        Box::new(a)
    }
}

// ───────────────────────── рукопожатие ─────────────────────────

struct HsReader<'a> {
    reader: &'a mut TlsReader,
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

fn first_cert(msg: &[u8]) -> Option<&[u8]> {
    // Certificate: ctx_len(1) ctx certs_len(3) [cert_len(3) cert ext_len(2) ext]...
    let b = &msg[4..];
    let ctx = *b.first()? as usize;
    let p = 1 + ctx + 3;
    let l = ((*b.get(p)? as usize) << 16) | ((*b.get(p + 1)? as usize) << 8) | *b.get(p + 2)? as usize;
    b.get(p + 3..p + 3 + l)
}

pub async fn connect(tcp: TcpStream, cfg: &RealityConfig) -> io::Result<RealityConn> {
    tcp.set_nodelay(true).ok();
    let (rd, mut wr) = tcp.into_split();

    let eph = StaticSecret::random_from_rng(rand::thread_rng());
    let eph_pub = PublicKey::from(&eph);
    let mut random = [0u8; 32];
    crate::common::random_bytes(&mut random);

    let body = build_client_hello(&random, eph_pub.as_bytes(), &cfg.server_name, &cfg.alpn);
    let mut hello = Vec::with_capacity(body.len() + 4);
    hello.push(0x01);
    hello.extend_from_slice(&[(body.len() >> 16) as u8, (body.len() >> 8) as u8, body.len() as u8]);
    hello.extend_from_slice(&body);

    // session_id REALITY
    let mut sid = [0u8; 32];
    sid[0] = VERSION[0];
    sid[1] = VERSION[1];
    sid[2] = VERSION[2];
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32;
    sid[4..8].copy_from_slice(&now.to_be_bytes());
    sid[8..16].copy_from_slice(&cfg.short_id);
    let shared = eph.diffie_hellman(&PublicKey::from(cfg.public_key));
    let mut auth_key = [0u8; 32];
    hkdf::Hkdf::<Sha256>::new(Some(&random[..20]), shared.as_bytes())
        .expand(b"REALITY", &mut auth_key)
        .unwrap();
    {
        let aead = Aes256Gcm::new_from_slice(&auth_key).unwrap();
        let nonce = aes_gcm::Nonce::from_slice(&random[20..32]);
        let mut pt = sid[..16].to_vec();
        // AAD — ClientHello с нулевым session_id (он уже нулевой в `hello`)
        let tag = aead.encrypt_in_place_detached(nonce, &hello, &mut pt).map_err(|_| io_err("seal"))?;
        sid[..16].copy_from_slice(&pt);
        sid[16..].copy_from_slice(&tag);
    }
    hello[39..71].copy_from_slice(&sid);

    let mut rec = vec![0x16, 0x03, 0x01, (hello.len() >> 8) as u8, hello.len() as u8];
    rec.extend_from_slice(&hello);
    wr.write_all(&rec).await?;

    let mut transcript = hello.clone();
    // Временный "нулевой" шифр, пока ключи не известны
    let dummy = RecordCipher::new(0x1301, HashAlg::Sha256, &[0u8; 32]);
    let mut reader = TlsReader { rd, raw: Vec::new(), cipher: dummy };

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
        return Err(io_err("REALITY: лишние данные после ServerHello"));
    }

    let mut verified = false;
    loop {
        let msg = hs.next_msg(true).await?;
        match msg[0] {
            8 => transcript.extend_from_slice(&msg), // EncryptedExtensions
            11 => {
                if let Some((pk, sig)) = first_cert(&msg).and_then(cert_ed25519) {
                    let mut m = <Hmac<Sha512> as Mac>::new_from_slice(&auth_key).unwrap();
                    m.update(&pk);
                    if m.finalize().into_bytes().as_slice() == sig.as_slice() {
                        verified = true;
                    }
                }
                transcript.extend_from_slice(&msg);
            }
            15 => transcript.extend_from_slice(&msg), // CertificateVerify
            20 => {
                let fk = hash.expand_label(&s_hs, "finished", &[], hl);
                let expect = hash.hmac(&fk, &hash.hash(&transcript));
                if msg[4..] != expect[..] {
                    return Err(io_err("REALITY: неверный Finished сервера"));
                }
                transcript.extend_from_slice(&msg);
                break;
            }
            13 => return Err(io_err("REALITY: сервер запросил клиентский сертификат")),
            t => return Err(io_err(format!("REALITY: неожиданное сообщение {t}"))),
        }
    }
    if !verified {
        return Err(io_err(
            "REALITY: проверка не пройдена — сервер ответил как обычный сайт (неверные pbk/sid/sni или рассинхрон времени)",
        ));
    }
    let leftover = std::mem::take(&mut hs.buf);
    if !leftover.is_empty() {
        log::debug!("REALITY: {} лишних байт handshake после Finished", leftover.len());
    }

    let th_fin = hash.hash(&transcript);
    let derived2 = hash.expand_label(&hs_secret, "derived", &hash.hash(&[]), hl);
    let master = hash.extract(&derived2, &vec![0u8; hl]);
    let c_ap = hash.expand_label(&master, "c ap traffic", &th_fin, hl);
    let s_ap = hash.expand_label(&master, "s ap traffic", &th_fin, hl);

    // Клиентский Finished
    let fk = hash.expand_label(&c_hs, "finished", &[], hl);
    let verify = hash.hmac(&fk, &th_fin);
    let mut fin = vec![20, 0, 0, hl as u8];
    fin.extend_from_slice(&verify);
    let mut c_hs_cipher = RecordCipher::new(suite, hash, &c_hs);
    let mut out = vec![0x14, 0x03, 0x03, 0x00, 0x01, 0x01];
    out.extend_from_slice(&c_hs_cipher.seal(0x16, &fin));
    wr.write_all(&out).await?;

    reader.cipher = RecordCipher::new(suite, hash, &s_ap);
    let writer = TlsWriter { wr, cipher: RecordCipher::new(suite, hash, &c_ap) };
    Ok(RealityConn { reader, writer })
}

#[cfg(test)]
mod tests {
    use super::*;

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
