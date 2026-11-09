//! Слой защищённых записей в формате TLS (application_data 23 3 3 len):
//! TLS 1.3 / REALITY и VLESS Encryption. Чтение и запись независимы, есть
//! доступ к «сырому» нижнему потоку — это нужно для XTLS Vision (direct).

use std::io;

use aes::cipher::{KeyIvInit, StreamCipher};
use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::ChaCha20Poly1305;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha384};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::common::{io_err, BoxStream};

pub const MAX_PLAINTEXT: usize = 16384;

/// BLAKE3 DeriveKey с произвольными байтами контекста (как в Go `blake3.DeriveKey`).
pub(crate) fn blake3_derive(ctx: &[u8], key: &[u8]) -> [u8; 32] {
    // blake3 принимает контекст как &str, но использует только его байты;
    // контекст здесь — двоичные данные (iv, открытые ключи), как в Xray.
    let ctx_str = unsafe { std::str::from_utf8_unchecked(ctx) };
    blake3::derive_key(ctx_str, key)
}


#[derive(Clone, Copy, PartialEq, Debug)]
pub(crate) enum HashAlg {
    Sha256,
    Sha384,
}

impl HashAlg {
    pub(crate) fn len(self) -> usize {
        match self {
            HashAlg::Sha256 => 32,
            HashAlg::Sha384 => 48,
        }
    }
    pub(crate) fn hash(self, data: &[u8]) -> Vec<u8> {
        match self {
            HashAlg::Sha256 => Sha256::digest(data).to_vec(),
            HashAlg::Sha384 => Sha384::digest(data).to_vec(),
        }
    }
    pub(crate) fn hmac(self, key: &[u8], data: &[u8]) -> Vec<u8> {
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
    pub(crate) fn extract(self, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        let zero = vec![0u8; self.len()];
        let salt = if salt.is_empty() { &zero[..] } else { salt };
        self.hmac(salt, ikm)
    }
    pub(crate) fn expand(self, prk: &[u8], info: &[u8], len: usize) -> Vec<u8> {
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
    pub(crate) fn expand_label(self, secret: &[u8], label: &str, ctx: &[u8], len: usize) -> Vec<u8> {
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
    pub(crate) fn new(suite: u16, hash: HashAlg, secret: &[u8]) -> Self {
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

    /// Шифр VLESS Encryption: ключ = BLAKE3-DeriveKey(ctx, key), счётчик nonce с 1.
    pub(crate) fn vless(ctx: &[u8], key: &[u8]) -> Self {
        let k = blake3_derive(ctx, key);
        Self { aead: Aead::A256(Box::new(Aes256Gcm::new_from_slice(&k).unwrap())), iv: [0u8; 12], seq: 1 }
    }

    fn nonce(&self) -> [u8; 12] {
        let mut n = self.iv;
        let s = self.seq.to_be_bytes();
        for i in 0..8 {
            n[4 + i] ^= s[i];
        }
        n
    }

    fn seal_raw(&mut self, nonce: &[u8; 12], aad: &[u8], buf: &mut Vec<u8>) {
        let n = aes_gcm::Nonce::from_slice(nonce);
        let tag = match &self.aead {
            Aead::A128(c) => c.encrypt_in_place_detached(n, aad, buf),
            Aead::A256(c) => c.encrypt_in_place_detached(n, aad, buf),
            Aead::Chacha(c) => c.encrypt_in_place_detached(n, aad, buf),
        }
        .expect("encrypt");
        buf.extend_from_slice(&tag);
    }

    fn open_raw(&mut self, nonce: &[u8; 12], aad: &[u8], buf: &mut Vec<u8>) -> io::Result<()> {
        if buf.len() < 16 {
            return Err(io_err("короткий зашифрованный блок"));
        }
        let tag_pos = buf.len() - 16;
        let tag = aes_gcm::Tag::clone_from_slice(&buf[tag_pos..]);
        buf.truncate(tag_pos);
        let n = aes_gcm::Nonce::from_slice(nonce);
        match &self.aead {
            Aead::A128(c) => c.decrypt_in_place_detached(n, aad, buf, &tag),
            Aead::A256(c) => c.decrypt_in_place_detached(n, aad, buf, &tag),
            Aead::Chacha(c) => c.decrypt_in_place_detached(n, aad, buf, &tag),
        }
        .map_err(|_| io_err("ошибка расшифровки (bad_record_mac)"))
    }

    /// Шифрование с очередным nonce (без заголовка записи).
    pub(crate) fn seal_next(&mut self, data: &[u8], aad: &[u8]) -> Vec<u8> {
        let nonce = self.nonce();
        self.seq += 1;
        let mut b = data.to_vec();
        self.seal_raw(&nonce, aad, &mut b);
        b
    }

    pub(crate) fn open_next(&mut self, data: &[u8], aad: &[u8]) -> io::Result<Vec<u8>> {
        let nonce = self.nonce();
        self.seq += 1;
        let mut b = data.to_vec();
        self.open_raw(&nonce, aad, &mut b)?;
        Ok(b)
    }

    pub(crate) fn open_with(&mut self, nonce: &[u8; 12], data: &[u8], aad: &[u8]) -> io::Result<Vec<u8>> {
        let mut b = data.to_vec();
        self.open_raw(nonce, aad, &mut b)?;
        Ok(b)
    }

    /// Шифрует plaintext||type и возвращает готовую TLS-запись.
    pub(crate) fn seal(&mut self, content_type: u8, data: &[u8]) -> Vec<u8> {
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
    pub(crate) fn open(&mut self, header: &[u8; 5], payload: &mut Vec<u8>) -> io::Result<u8> {
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


#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RecordKind {
    /// TLS 1.3: plaintext||content_type, с удалением нулевого паддинга
    Tls13,
    /// VLESS Encryption: только данные
    VlessEnc,
}

pub(crate) type Ctr = ctr::Ctr128BE<aes::Aes256>;

/// AES-256-CTR с ключом BLAKE3-DeriveKey("VLESS", key) — `NewCTR` из Xray.
pub(crate) fn vless_ctr(key: &[u8], iv: &[u8]) -> Ctr {
    let k = blake3::derive_key("VLESS", key);
    Ctr::new_from_slices(&k, &iv[..16]).unwrap()
}

/// `XorConn` из Xray: XOR только 5-байтовых заголовков записей (режим random).
pub(crate) struct XorState {
    ctr: Ctr,
    skip: usize,
    header: Vec<u8>,
}

fn header_len(h: &[u8]) -> usize {
    if h[0] == 23 && h[1] == 3 && h[2] == 3 {
        ((h[3] as usize) << 8) | h[4] as usize
    } else {
        0
    }
}

impl XorState {
    pub(crate) fn new(ctr: Ctr, skip: usize) -> Self {
        Self { ctr, skip, header: Vec::with_capacity(5) }
    }

    /// Исходящие данные: заголовок определяется по открытому тексту, затем XOR.
    pub(crate) fn process_out(&mut self, b: &mut [u8]) {
        let mut p = 0;
        loop {
            let rest = b.len() - p;
            if rest <= self.skip {
                self.skip -= rest;
                break;
            }
            p += self.skip;
            self.skip = 0;
            let need = 5 - self.header.len();
            if b.len() - p < need {
                self.header.extend_from_slice(&b[p..]);
                self.ctr.apply_keystream(&mut b[p..]);
                break;
            }
            self.header.extend_from_slice(&b[p..p + need]);
            self.skip = header_len(&self.header);
            self.header.clear();
            self.ctr.apply_keystream(&mut b[p..p + need]);
            p += need;
        }
    }

    /// Входящие данные: сначала XOR, затем разбор заголовка.
    pub(crate) fn process_in(&mut self, b: &mut [u8]) {
        let mut p = 0;
        loop {
            let rest = b.len() - p;
            if rest <= self.skip {
                self.skip -= rest;
                break;
            }
            p += self.skip;
            self.skip = 0;
            let need = 5 - self.header.len();
            if b.len() - p < need {
                self.ctr.apply_keystream(&mut b[p..]);
                self.header.extend_from_slice(&b[p..]);
                break;
            }
            self.ctr.apply_keystream(&mut b[p..p + need]);
            self.header.extend_from_slice(&b[p..p + need]);
            self.skip = header_len(&self.header);
            self.header.clear();
            p += need;
        }
    }
}

pub type BoxRead = Box<dyn AsyncRead + Unpin + Send>;
pub type BoxWrite = Box<dyn AsyncWrite + Unpin + Send>;

pub struct SecureReader {
    pub(crate) rd: BoxRead,
    pub(crate) raw: Vec<u8>,
    pub(crate) cipher: RecordCipher,
    pub(crate) kind: RecordKind,
    pub(crate) xor: Option<XorState>,
    /// VLESS Encryption 1-RTT: длина зашифрованного паддинга сервера перед записями
    pub(crate) pre_padding: usize,
}

impl SecureReader {
    pub(crate) fn new(rd: BoxRead, cipher: RecordCipher, kind: RecordKind) -> Self {
        Self { rd, raw: Vec::new(), cipher, kind, xor: None, pre_padding: 0 }
    }

    async fn read_some(&mut self) -> io::Result<bool> {
        let mut tmp = vec![0u8; 32 * 1024];
        let n = self.rd.read(&mut tmp).await?;
        if n == 0 {
            return Ok(false);
        }
        if let Some(x) = &mut self.xor {
            x.process_in(&mut tmp[..n]);
        }
        self.raw.extend_from_slice(&tmp[..n]);
        Ok(true)
    }

    pub(crate) async fn fill(&mut self, need: usize) -> io::Result<bool> {
        while self.raw.len() < need {
            if !self.read_some().await? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Читает ровно n байт из буфера/потока.
    pub(crate) async fn take_exact(&mut self, n: usize) -> io::Result<Vec<u8>> {
        if !self.fill(n).await? {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "соединение закрыто"));
        }
        Ok(self.raw.drain(..n).collect())
    }

    /// Одна сырая запись: (тип, заголовок, тело).
    pub(crate) async fn read_raw_record(&mut self) -> io::Result<Option<(u8, [u8; 5], Vec<u8>)>> {
        if !self.fill(5).await? {
            return Ok(None);
        }
        let header: [u8; 5] = self.raw[..5].try_into().unwrap();
        let len = u16::from_be_bytes([header[3], header[4]]) as usize;
        if len > MAX_PLAINTEXT + 2048 {
            return Err(io_err("запись слишком большая"));
        }
        if !self.fill(5 + len).await? {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "обрыв записи"));
        }
        let body = self.raw[5..5 + len].to_vec();
        self.raw.drain(..5 + len);
        Ok(Some((header[0], header, body)))
    }

    /// Очередная порция данных приложения. None — конец потока.
    pub async fn read_app(&mut self) -> io::Result<Option<Vec<u8>>> {
        if self.pre_padding > 0 {
            let n = self.pre_padding;
            self.pre_padding = 0;
            let p = self.take_exact(n).await?;
            self.cipher.open_next(&p, &[])?;
        }
        loop {
            let Some((typ, header, mut body)) = self.read_raw_record().await? else {
                return Ok(None);
            };
            if self.kind == RecordKind::VlessEnc {
                if header[..3] != [23, 3, 3] || body.len() < 17 {
                    return Err(io_err("VLESS Encryption: неверный заголовок записи"));
                }
                let d = self.cipher.open_next(&body, &header)?;
                if d.is_empty() {
                    continue;
                }
                return Ok(Some(d));
            }
            match typ {
                0x14 => continue,
                0x17 => {
                    let inner = self.cipher.open(&header, &mut body)?;
                    match inner {
                        0x17 => {
                            if body.is_empty() {
                                continue;
                            }
                            return Ok(Some(body));
                        }
                        0x16 => continue,
                        0x15 => return Ok(None),
                        _ => return Err(io_err("TLS: неизвестный тип записи")),
                    }
                }
                0x15 => return Ok(None),
                _ => return Err(io_err(format!("TLS: неожиданная запись {typ:#x}"))),
            }
        }
    }

    /// Сырые, ещё не расшифрованные байты (переход Vision в direct).
    pub fn take_raw(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.raw)
    }

    /// Чтение из нижнего потока (после перехода в direct).
    pub async fn read_raw(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if !self.raw.is_empty() {
            let n = self.raw.len().min(buf.len());
            buf[..n].copy_from_slice(&self.raw[..n]);
            self.raw.drain(..n);
            return Ok(n);
        }
        let n = self.rd.read(buf).await?;
        if let Some(x) = &mut self.xor {
            x.process_in(&mut buf[..n]);
        }
        Ok(n)
    }
}

pub struct SecureWriter {
    pub(crate) wr: BoxWrite,
    pub(crate) cipher: RecordCipher,
    pub(crate) kind: RecordKind,
    pub(crate) xor: Option<XorState>,
    /// Байты, которые нужно отправить перед первой записью
    pub(crate) pre_write: Vec<u8>,
}

impl SecureWriter {
    pub(crate) fn new(wr: BoxWrite, cipher: RecordCipher, kind: RecordKind) -> Self {
        Self { wr, cipher, kind, xor: None, pre_write: Vec::new() }
    }

    async fn send(&mut self, mut out: Vec<u8>) -> io::Result<()> {
        if let Some(x) = &mut self.xor {
            x.process_out(&mut out);
        }
        if !self.pre_write.is_empty() {
            let mut v = std::mem::take(&mut self.pre_write);
            v.extend_from_slice(&out);
            out = v;
        }
        self.wr.write_all(&out).await
    }

    pub async fn write_app(&mut self, data: &[u8]) -> io::Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        let mut out = Vec::with_capacity(data.len() + 64);
        match self.kind {
            RecordKind::Tls13 => {
                for chunk in data.chunks(MAX_PLAINTEXT) {
                    out.extend_from_slice(&self.cipher.seal(0x17, chunk));
                }
            }
            RecordKind::VlessEnc => {
                for chunk in data.chunks(8192) {
                    let l = chunk.len() + 16;
                    let header = [23u8, 3, 3, (l >> 8) as u8, l as u8];
                    out.extend_from_slice(&header);
                    out.extend_from_slice(&self.cipher.seal_next(chunk, &header));
                }
            }
        }
        self.send(out).await
    }

    pub async fn write_raw(&mut self, data: &[u8]) -> io::Result<()> {
        self.send(data.to_vec()).await
    }

    pub async fn close(&mut self) {
        if self.kind == RecordKind::Tls13 {
            let rec = self.cipher.seal(0x15, &[0x01, 0x00]);
            let _ = self.send(rec).await;
        }
        let _ = self.wr.shutdown().await;
    }

    pub async fn shutdown_raw(&mut self) {
        let _ = self.wr.shutdown().await;
    }
}

pub struct SecureConn {
    pub reader: SecureReader,
    pub writer: SecureWriter,
}

impl SecureConn {
    /// Превращает соединение в обычный поток (через внутренний канал).
    pub fn into_stream(self) -> BoxStream {
        let (a, b) = tokio::io::duplex(128 * 1024);
        let (mut br, mut bw) = tokio::io::split(b);
        let SecureConn { mut reader, mut writer } = self;
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
            loop {
                match reader.read_app().await {
                    Ok(Some(d)) => {
                        if bw.write_all(&d).await.is_err() {
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        log::debug!("{e}");
                        break;
                    }
                }
            }
            let _ = bw.shutdown().await;
        });
        Box::new(a)
    }
}

pub fn split(s: BoxStream) -> (BoxRead, BoxWrite) {
    let (r, w) = tokio::io::split(s);
    (Box::new(r), Box::new(w))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xor_roundtrip() {
        let key = [3u8; 32];
        let iv = [5u8; 16];
        let mut data = vec![23u8, 3, 3, 0, 3, 1, 2, 3, 23, 3, 3, 0, 1, 9];
        let orig = data.clone();
        let mut w = XorState::new(vless_ctr(&key, &iv), 0);
        w.process_out(&mut data[..7]);
        w.process_out(&mut data[7..]);
        assert_ne!(data, orig);
        assert_eq!(&data[5..8], &orig[5..8]);
        let mut r = XorState::new(vless_ctr(&key, &iv), 0);
        r.process_in(&mut data[..3]);
        r.process_in(&mut data[3..]);
        assert_eq!(data, orig);
    }

    #[test]
    fn vless_cipher_nonce_starts_at_one() {
        let mut a = RecordCipher::vless(b"ctx", &[1u8; 32]);
        let mut b = RecordCipher::vless(b"ctx", &[1u8; 32]);
        let ct = a.seal_next(b"hi", b"aad");
        let mut one = [0u8; 12];
        one[11] = 1;
        assert_eq!(b.open_with(&one, &ct, b"aad").unwrap(), b"hi");
    }
}
