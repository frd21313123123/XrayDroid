//! VMess AEAD (alterId = 0): заголовок AEAD, поток чанков с маскированием длины
//! (shake128) и глобальным паддингом — как в Xray-core.

use std::io;

use aes::cipher::BlockEncrypt;
use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::Aes128Gcm;
use chacha20poly1305::ChaCha20Poly1305;
use md5::Md5;
use rand::Rng;
use sha2::{Digest, Sha256};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::common::{io_err, random_bytes, Address, BoxStream};
use crate::config::Profile;
use crate::transport;

const MAX_CHUNK: usize = 8192 - 16 - 2 - 64;

// ───────────── KDF: вложенный HMAC-SHA256 ─────────────

fn kdf_hash(level: usize, keys: &[&[u8]], msg: &[u8]) -> [u8; 32] {
    if level == 0 {
        return Sha256::digest(msg).into();
    }
    let k = keys[level - 1];
    let h = |m: &[u8]| kdf_hash(level - 1, keys, m);
    let mut kb = [0u8; 64];
    if k.len() > 64 {
        kb[..32].copy_from_slice(&h(k));
    } else {
        kb[..k.len()].copy_from_slice(k);
    }
    let mut inner = Vec::with_capacity(64 + msg.len());
    inner.extend(kb.iter().map(|b| b ^ 0x36));
    inner.extend_from_slice(msg);
    let ih = h(&inner);
    let mut outer = Vec::with_capacity(96);
    outer.extend(kb.iter().map(|b| b ^ 0x5c));
    outer.extend_from_slice(&ih);
    h(&outer)
}

pub fn kdf(key: &[u8], path: &[&[u8]]) -> [u8; 32] {
    let mut keys: Vec<&[u8]> = vec![b"VMess AEAD KDF"];
    keys.extend_from_slice(path);
    kdf_hash(keys.len(), &keys, key)
}

fn kdf16(key: &[u8], path: &[&[u8]]) -> [u8; 16] {
    kdf(key, path)[..16].try_into().unwrap()
}

fn fnv1a32(data: &[u8]) -> u32 {
    let mut h: u32 = 0x811c9dc5;
    for b in data {
        h ^= *b as u32;
        h = h.wrapping_mul(0x01000193);
    }
    h
}

fn gcm_seal(key: &[u8; 16], nonce: &[u8], data: &[u8], aad: &[u8]) -> Vec<u8> {
    let c = Aes128Gcm::new_from_slice(key).unwrap();
    let mut buf = data.to_vec();
    let tag = c.encrypt_in_place_detached(aes_gcm::Nonce::from_slice(nonce), aad, &mut buf).unwrap();
    buf.extend_from_slice(&tag);
    buf
}

fn gcm_open(key: &[u8; 16], nonce: &[u8], data: &[u8], aad: &[u8]) -> io::Result<Vec<u8>> {
    if data.len() < 16 {
        return Err(io_err("VMess: короткий блок"));
    }
    let c = Aes128Gcm::new_from_slice(key).unwrap();
    let mut buf = data[..data.len() - 16].to_vec();
    let tag = aes_gcm::Tag::clone_from_slice(&data[data.len() - 16..]);
    c.decrypt_in_place_detached(aes_gcm::Nonce::from_slice(nonce), aad, &mut buf, &tag)
        .map_err(|_| io_err("VMess: ошибка расшифровки (неверный UUID или время на устройстве)"))?;
    Ok(buf)
}

fn seal_header(cmd_key: &[u8; 16], header: &[u8]) -> Vec<u8> {
    // AuthID
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    let mut a = [0u8; 16];
    a[..8].copy_from_slice(&now.to_be_bytes());
    random_bytes(&mut a[8..12]);
    let crc = crc32fast::hash(&a[..12]);
    a[12..].copy_from_slice(&crc.to_be_bytes());
    let block_key = kdf16(cmd_key, &[b"AES Auth ID Encryption"]);
    let cipher = aes::Aes128::new_from_slice(&block_key).unwrap();
    let mut blk = aes::Block::clone_from_slice(&a);
    cipher.encrypt_block(&mut blk);
    let auth_id: [u8; 16] = blk.into();

    let mut nonce = [0u8; 8];
    random_bytes(&mut nonce);

    let len_key = kdf16(cmd_key, &[b"VMess Header AEAD Key_Length", &auth_id, &nonce]);
    let len_iv = kdf(cmd_key, &[b"VMess Header AEAD Nonce_Length", &auth_id, &nonce]);
    let enc_len = gcm_seal(&len_key, &len_iv[..12], &(header.len() as u16).to_be_bytes(), &auth_id);

    let p_key = kdf16(cmd_key, &[b"VMess Header AEAD Key", &auth_id, &nonce]);
    let p_iv = kdf(cmd_key, &[b"VMess Header AEAD Nonce", &auth_id, &nonce]);
    let enc = gcm_seal(&p_key, &p_iv[..12], header, &auth_id);

    let mut out = Vec::with_capacity(16 + 18 + 8 + enc.len());
    out.extend_from_slice(&auth_id);
    out.extend_from_slice(&enc_len);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&enc);
    out
}

// ───────────── поток чанков ─────────────

enum BodyAead {
    Aes(Box<Aes128Gcm>),
    Chacha(Box<ChaCha20Poly1305>),
    /// security = none: чанки с маскированной длиной, без шифрования и паддинга
    Plain,
}

const SEC_AES: u8 = 3;
const SEC_CHACHA: u8 = 4;
const SEC_NONE: u8 = 5;

struct Shake(sha3::Shake128Reader);

impl Shake {
    fn new(iv: &[u8]) -> Self {
        let mut h = sha3::Shake128::default();
        h.update(iv);
        Shake(h.finalize_xof())
    }
    fn next(&mut self) -> u16 {
        let mut b = [0u8; 2];
        self.0.read(&mut b);
        u16::from_be_bytes(b)
    }
}

struct Chunker {
    aead: BodyAead,
    iv: [u8; 16],
    count: u16,
    shake: Shake,
}

impl Chunker {
    fn new(security: u8, key: &[u8; 16], iv: &[u8; 16]) -> Self {
        let aead = if security == SEC_NONE {
            BodyAead::Plain
        } else if security == SEC_CHACHA {
            let a = Md5::digest(key);
            let b = Md5::digest(a);
            let mut k = [0u8; 32];
            k[..16].copy_from_slice(&a);
            k[16..].copy_from_slice(&b);
            BodyAead::Chacha(Box::new(ChaCha20Poly1305::new_from_slice(&k).unwrap()))
        } else {
            BodyAead::Aes(Box::new(Aes128Gcm::new_from_slice(key).unwrap()))
        };
        Self { aead, iv: *iv, count: 0, shake: Shake::new(iv) }
    }

    fn nonce(&mut self) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[..2].copy_from_slice(&self.count.to_be_bytes());
        n[2..].copy_from_slice(&self.iv[2..12]);
        self.count = self.count.wrapping_add(1);
        n
    }

    fn seal(&mut self, data: &[u8], out: &mut Vec<u8>) {
        if let BodyAead::Plain = self.aead {
            let mask = self.shake.next();
            out.extend_from_slice(&((data.len() as u16) ^ mask).to_be_bytes());
            out.extend_from_slice(data);
            return;
        }
        let pad = (self.shake.next() % 64) as usize;
        let mask = self.shake.next();
        let size = (data.len() + 16 + pad) as u16;
        out.extend_from_slice(&(size ^ mask).to_be_bytes());
        let nonce = self.nonce();
        let mut buf = data.to_vec();
        let n = aes_gcm::Nonce::from_slice(&nonce);
        let tag = match &self.aead {
            BodyAead::Aes(c) => c.encrypt_in_place_detached(n, &[], &mut buf),
            BodyAead::Chacha(c) => c.encrypt_in_place_detached(n, &[], &mut buf),
            BodyAead::Plain => unreachable!(),
        }
        .unwrap();
        out.extend_from_slice(&buf);
        out.extend_from_slice(&tag);
        let start = out.len();
        out.resize(start + pad, 0);
        rand::thread_rng().fill(&mut out[start..]);
    }

    /// None — конец потока (пустой чанк).
    async fn open<R: AsyncRead + Unpin>(&mut self, r: &mut R) -> io::Result<Option<Vec<u8>>> {
        if let BodyAead::Plain = self.aead {
            let mask = self.shake.next();
            let size = match r.read_u16().await {
                Ok(s) => (s ^ mask) as usize,
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
                Err(e) => return Err(e),
            };
            if size == 0 {
                return Ok(None);
            }
            let mut buf = vec![0u8; size];
            r.read_exact(&mut buf).await?;
            return Ok(Some(buf));
        }
        let pad = (self.shake.next() % 64) as usize;
        let mask = self.shake.next();
        let size = match r.read_u16().await {
            Ok(s) => (s ^ mask) as usize,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e),
        };
        if size < 16 + pad {
            return Err(io_err("VMess: неверный размер чанка"));
        }
        let mut buf = vec![0u8; size];
        r.read_exact(&mut buf).await?;
        buf.truncate(size - pad);
        let tag_pos = buf.len() - 16;
        let tag = aes_gcm::Tag::clone_from_slice(&buf[tag_pos..]);
        buf.truncate(tag_pos);
        let nonce = self.nonce();
        let n = aes_gcm::Nonce::from_slice(&nonce);
        match &self.aead {
            BodyAead::Aes(c) => c.decrypt_in_place_detached(n, &[], &mut buf, &tag),
            BodyAead::Chacha(c) => c.decrypt_in_place_detached(n, &[], &mut buf, &tag),
            BodyAead::Plain => unreachable!(),
        }
        .map_err(|_| io_err("VMess: ошибка расшифровки чанка"))?;
        if buf.is_empty() {
            return Ok(None);
        }
        Ok(Some(buf))
    }
}

struct Session {
    req_key: [u8; 16],
    req_iv: [u8; 16],
    resp_key: [u8; 16],
    resp_iv: [u8; 16],
    resp_v: u8,
    security: u8,
}

fn build_request(p: &Profile, cmd: u8, dest: &Address) -> io::Result<(Vec<u8>, Session)> {
    let uuid = super::vless::parse_uuid(&p.id_or_password)?;
    let mut h = Md5::new();
    md5::Digest::update(&mut h, uuid);
    md5::Digest::update(&mut h, b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
    let cmd_key: [u8; 16] = h.finalize().into();

    // none и zero — без шифрования тела (его защищает TLS); zero в Xray ещё и без чанков,
    // но чанки нужны для UDP и корректного завершения потока, поэтому zero идёт как none
    let security = match p.method.to_lowercase().as_str() {
        "chacha20-poly1305" | "chacha20-ietf-poly1305" => SEC_CHACHA,
        "none" | "zero" => SEC_NONE,
        _ => SEC_AES, // auto / aes-128-gcm
    };
    let mut req_key = [0u8; 16];
    let mut req_iv = [0u8; 16];
    random_bytes(&mut req_key);
    random_bytes(&mut req_iv);
    let resp_v: u8 = rand::thread_rng().gen();
    let resp_key: [u8; 16] = Sha256::digest(req_key)[..16].try_into().unwrap();
    let resp_iv: [u8; 16] = Sha256::digest(req_iv)[..16].try_into().unwrap();

    let pad_len: u8 = rand::thread_rng().gen_range(0..16);
    let mut hdr = Vec::with_capacity(96);
    hdr.push(1);
    hdr.extend_from_slice(&req_iv);
    hdr.extend_from_slice(&req_key);
    hdr.push(resp_v);
    // ChunkStream | ChunkMasking (| GlobalPadding — только с шифрованием, как в Xray)
    hdr.push(if security == SEC_NONE { 0x01 | 0x04 } else { 0x01 | 0x04 | 0x08 });
    hdr.push((pad_len << 4) | security);
    hdr.push(0);
    hdr.push(cmd);
    dest.write_vless(&mut hdr);
    let mut padding = vec![0u8; pad_len as usize];
    random_bytes(&mut padding);
    hdr.extend_from_slice(&padding);
    let f = fnv1a32(&hdr);
    hdr.extend_from_slice(&f.to_be_bytes());

    Ok((seal_header(&cmd_key, &hdr), Session { req_key, req_iv, resp_key, resp_iv, resp_v, security }))
}

async fn read_response<R: AsyncRead + Unpin>(r: &mut R, s: &Session) -> io::Result<()> {
    let len_key = kdf16(&s.resp_key, &[b"AEAD Resp Header Len Key"]);
    let len_iv = kdf(&s.resp_iv, &[b"AEAD Resp Header Len IV"]);
    let mut lb = [0u8; 18];
    r.read_exact(&mut lb).await?;
    let l = gcm_open(&len_key, &len_iv[..12], &lb, &[])?;
    let len = u16::from_be_bytes([l[0], l[1]]) as usize;
    let p_key = kdf16(&s.resp_key, &[b"AEAD Resp Header Key"]);
    let p_iv = kdf(&s.resp_iv, &[b"AEAD Resp Header IV"]);
    let mut pb = vec![0u8; len + 16];
    r.read_exact(&mut pb).await?;
    let h = gcm_open(&p_key, &p_iv[..12], &pb, &[])?;
    if h.first() != Some(&s.resp_v) {
        return Err(io_err("VMess: неверный заголовок ответа"));
    }
    Ok(())
}

async fn run<S>(app: BoxStream, server: S, request: Vec<u8>, s: Session) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let (mut ar, mut aw) = tokio::io::split(app);
    let (mut sr, mut sw) = tokio::io::split(server);
    let mut up_chunks = Chunker::new(s.security, &s.req_key, &s.req_iv);
    let mut down_chunks = Chunker::new(s.security, &s.resp_key, &s.resp_iv);
    let up = async move {
        let mut out = request;
        let first = super::vless::first_payload(&mut ar, 50).await?;
        if !first.is_empty() {
            for c in first.chunks(MAX_CHUNK) {
                up_chunks.seal(c, &mut out);
            }
        }
        sw.write_all(&out).await?;
        let mut buf = vec![0u8; MAX_CHUNK];
        loop {
            let n = ar.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            let mut o = Vec::with_capacity(n + 100);
            up_chunks.seal(&buf[..n], &mut o);
            sw.write_all(&o).await?;
        }
        let mut o = Vec::new();
        up_chunks.seal(&[], &mut o);
        let _ = sw.write_all(&o).await;
        Ok::<_, io::Error>(())
    };
    let down = async move {
        read_response(&mut sr, &s).await?;
        while let Some(d) = down_chunks.open(&mut sr).await? {
            aw.write_all(&d).await?;
        }
        let _ = aw.shutdown().await;
        Ok::<_, io::Error>(())
    };
    crate::common::join_halves(up, down).await
}

pub async fn tcp(p: &Profile, app: BoxStream, dest: &Address) -> io::Result<()> {
    let (req, s) = build_request(p, 1, dest)?;
    let server = transport::dial(p).await?;
    run(app, server, req, s).await
}

pub async fn udp(p: &Profile, app: BoxStream, dest: &Address) -> io::Result<()> {
    // каждый чанк — одна датаграмма; логика та же
    let (req, s) = build_request(p, 2, dest)?;
    let server = transport::dial(p).await?;
    run(app, server, req, s).await
}
