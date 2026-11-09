//! VLESS Encryption (`encryption=mlkem768x25519plus.<native|xorpub|random>.<1rtt|0rtt>.[паддинг.]ключи`)
//! — клиент, совместимый с Xray-core (`proxy/vless/encryption`). Всегда 1-RTT
//! (0-RTT-тикеты — только оптимизация, сервер принимает и полное рукопожатие).

use std::io;
use std::time::Duration;

use aes::cipher::StreamCipher;
use base64::Engine;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
use rand::Rng;
use tokio::io::AsyncWriteExt;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::common::{io_err, random_bytes, BoxStream};
use crate::transport::secure::{self, vless_ctr, RecordCipher, RecordKind, SecureConn, SecureReader, SecureWriter, XorState};

#[derive(Clone, Debug)]
pub struct EncConfig {
    pub keys: Vec<Vec<u8>>,
    /// 0 — native, 1 — xorpub, 2 — random
    pub xor_mode: u32,
    pub padding_lens: Vec<[i64; 3]>,
    pub padding_gaps: Vec<[i64; 3]>,
}

/// Разбор поля encryption. None — шифрования нет ("none").
pub fn parse(enc: &str) -> io::Result<Option<EncConfig>> {
    let enc = enc.trim();
    if enc.is_empty() || enc == "none" {
        return Ok(None);
    }
    let s: Vec<&str> = enc.split('.').collect();
    let bad = || io_err("VLESS Encryption: неверная строка encryption");
    if s.len() < 4 || s[0] != "mlkem768x25519plus" {
        return Err(bad());
    }
    let xor_mode = match s[1] {
        "native" => 0,
        "xorpub" => 1,
        "random" => 2,
        _ => return Err(bad()),
    };
    if s[2] != "1rtt" && s[2] != "0rtt" {
        return Err(bad());
    }
    let mut padding = Vec::new();
    let mut keys = Vec::new();
    for r in &s[3..] {
        if r.len() < 20 {
            padding.push(*r);
            continue;
        }
        let b = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(r.trim_end_matches('=')).map_err(|_| bad())?;
        if b.len() != 32 && b.len() != 1184 {
            return Err(bad());
        }
        keys.push(b);
    }
    if keys.is_empty() {
        return Err(bad());
    }
    let mut cfg = EncConfig { keys, xor_mode, padding_lens: vec![], padding_gaps: vec![] };
    for (i, p) in padding.iter().enumerate() {
        let x: Vec<i64> = p.split('-').filter_map(|v| v.parse().ok()).collect();
        if x.len() < 3 {
            return Err(io_err("VLESS Encryption: неверный параметр паддинга"));
        }
        let y = [x[0], x[1], x[2]];
        if i % 2 == 0 {
            cfg.padding_lens.push(y);
        } else {
            cfg.padding_gaps.push(y);
        }
    }
    Ok(Some(cfg))
}

fn rand_between(a: i64, b: i64) -> i64 {
    if b <= a {
        return a;
    }
    rand::thread_rng().gen_range(a..b)
}

/// CreatPadding: длины фрагментов и паузы между ними.
fn create_padding(cfg: &EncConfig) -> (usize, Vec<usize>, Vec<Duration>) {
    let (lens, gaps): (Vec<[i64; 3]>, Vec<[i64; 3]>) = if cfg.padding_lens.is_empty() {
        (vec![[100, 111, 1111], [50, 0, 3333]], vec![[75, 0, 111]])
    } else {
        (cfg.padding_lens.clone(), cfg.padding_gaps.clone())
    };
    let mut total = 0;
    let mut out_l = Vec::new();
    for y in &lens {
        let l = if y[0] >= rand_between(0, 100) { rand_between(y[1], y[2]) as usize } else { 0 };
        out_l.push(l);
        total += l;
    }
    let mut out_g = Vec::new();
    for y in &gaps {
        let g = if y[0] >= rand_between(0, 100) { rand_between(y[1], y[2]) as u64 } else { 0 };
        out_g.push(Duration::from_millis(g));
    }
    (total, out_l, out_g)
}

fn len2(l: usize) -> [u8; 2] {
    [(l >> 8) as u8, l as u8]
}

/// Рукопожатие поверх транспортного потока; дальше — записи VLESS Encryption.
pub async fn handshake(io: BoxStream, cfg: &EncConfig) -> io::Result<SecureConn> {
    let (rd, mut wr) = secure::split(io);
    let (hello, head_len, mut lens, gaps, nfs_key, mut nfs, dk, xs, pfs_public, iv) = {
    let mut rng = rand::thread_rng();

    // ── ретрансляторы (relays) ──
    let relays_len: usize = cfg.keys.iter().map(|k| if k.len() == 32 { 64 } else { 1088 + 32 }).sum::<usize>() - 32;
    let mut iv = [0u8; 16];
    random_bytes(&mut iv);
    let mut relays = vec![0u8; relays_len];
    let mut nfs_key: Vec<u8> = Vec::new();
    let mut last_ctr: Option<secure::Ctr> = None;
    let mut off = 0;
    for (j, k) in cfg.keys.iter().enumerate() {
        let index;
        if k.len() == 32 {
            let eph = StaticSecret::random_from_rng(&mut rng);
            relays[off..off + 32].copy_from_slice(PublicKey::from(&eph).as_bytes());
            let pk: [u8; 32] = k[..].try_into().unwrap();
            nfs_key = eph.diffie_hellman(&PublicKey::from(pk)).as_bytes().to_vec();
            index = 32;
        } else {
            let enc = ml_kem::Encoded::<<MlKem768 as KemCore>::EncapsulationKey>::try_from(&k[..])
                .map_err(|_| io_err("VLESS Encryption: неверный ключ ML-KEM"))?;
            let ek = <MlKem768 as KemCore>::EncapsulationKey::from_bytes(&enc);
            let (ct, ss) = ek.encapsulate(&mut rng).map_err(|_| io_err("ML-KEM encapsulate"))?;
            relays[off..off + 1088].copy_from_slice(&ct);
            nfs_key = ss.to_vec();
            index = 1088;
        }
        if cfg.xor_mode > 0 {
            vless_ctr(k, &iv).apply_keystream(&mut relays[off..off + index]);
        }
        if let Some(c) = &mut last_ctr {
            c.apply_keystream(&mut relays[off..off + 32]);
        }
        if j == cfg.keys.len() - 1 {
            break;
        }
        let mut c = vless_ctr(&nfs_key, &iv);
        let mut h = *blake3::hash(&cfg.keys[j + 1]).as_bytes();
        c.apply_keystream(&mut h);
        relays[off + index..off + index + 32].copy_from_slice(&h);
        last_ctr = Some(c);
        off += index + 32;
    }
    let mut nfs = RecordCipher::vless(&iv, &nfs_key);

    // ── обмен ключами PFS: ML-KEM-768 + X25519 ──
    let (dk, ek) = MlKem768::generate(&mut rng);
    let xs = StaticSecret::random_from_rng(&mut rng);
    let mut pfs_public = ek.as_bytes().to_vec();
    pfs_public.extend_from_slice(PublicKey::from(&xs).as_bytes());

    let mut hello = Vec::with_capacity(16 + relays_len + 1250 + 2000);
    hello.extend_from_slice(&iv);
    hello.extend_from_slice(&relays);
    hello.extend_from_slice(&nfs.seal_next(&len2(1184 + 32 + 16), &[]));
    hello.extend_from_slice(&nfs.seal_next(&pfs_public, &[]));
    let head_len = hello.len();

    let (padding_len, mut lens, gaps) = create_padding(cfg);
    let padding_len = padding_len.max(35);
    if lens.iter().sum::<usize>() < padding_len {
        lens[0] += padding_len - lens.iter().sum::<usize>();
    }
    hello.extend_from_slice(&nfs.seal_next(&len2(padding_len - 18), &[]));
    hello.extend_from_slice(&nfs.seal_next(&vec![0u8; padding_len - 34], &[]));
    (hello, head_len, lens, gaps, nfs_key, nfs, dk, xs, pfs_public, iv)
    };

    // фрагментированная отправка с паузами
    lens[0] += head_len;
    let mut pos = 0;
    for (i, l) in lens.iter().enumerate() {
        if *l > 0 {
            let end = (pos + l).min(hello.len());
            wr.write_all(&hello[pos..end]).await?;
            pos = end;
        }
        if let Some(g) = gaps.get(i) {
            if !g.is_zero() {
                tokio::time::sleep(*g).await;
            }
        }
    }
    if pos < hello.len() {
        wr.write_all(&hello[pos..]).await?;
    }

    // ── ответ сервера ──
    let mut reader = SecureReader::new(rd, RecordCipher::vless(b"-", &[0u8; 32]), RecordKind::VlessEnc);
    let enc_pfs = reader.take_exact(1088 + 32 + 16).await?;
    let server_pfs = nfs
        .open_with(&[0xff; 12], &enc_pfs, &[])
        .map_err(|_| io_err("VLESS Encryption: неверный ответ сервера (ключи не совпадают?)"))?;
    let ct = ml_kem::Ciphertext::<MlKem768>::try_from(&server_pfs[..1088]).map_err(|_| io_err("ML-KEM ciphertext"))?;
    let mlkem_key = dk.decapsulate(&ct).map_err(|_| io_err("ML-KEM decapsulate"))?;
    let peer_x: [u8; 32] = server_pfs[1088..1120].try_into().unwrap();
    let x_key = xs.diffie_hellman(&PublicKey::from(peer_x));
    let mut united = Vec::with_capacity(96);
    united.extend_from_slice(&mlkem_key);
    united.extend_from_slice(x_key.as_bytes());
    united.extend_from_slice(&nfs_key);

    let mut peer = RecordCipher::vless(&server_pfs[..1120], &united);
    let ticket = peer.open_next(&reader.take_exact(32).await?, &[])?;
    let l = peer.open_next(&reader.take_exact(18).await?, &[])?;
    let padding = ((l[0] as usize) << 8) | l[1] as usize;
    reader.cipher = peer;
    reader.pre_padding = padding;

    let mut writer = SecureWriter::new(wr, RecordCipher::vless(&pfs_public, &united), RecordKind::VlessEnc);
    if cfg.xor_mode == 2 {
        writer.xor = Some(XorState::new(vless_ctr(&united, &iv), 0));
        let mut x = XorState::new(vless_ctr(&united, &ticket[..16]), padding);
        let mut rest = std::mem::take(&mut reader.raw);
        x.process_in(&mut rest);
        reader.raw = rest;
        reader.xor = Some(x);
    }
    Ok(SecureConn { reader, writer })
}

#[cfg(test)]
mod tests {
    #[test]
    fn parse_enc() {
        let k = base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, [7u8; 32]);
        let c = super::parse(&format!("mlkem768x25519plus.random.0rtt.100-111-1111.75-0-111.{k}")).unwrap().unwrap();
        assert_eq!(c.xor_mode, 2);
        assert_eq!(c.keys.len(), 1);
        assert_eq!(c.padding_lens.len(), 1);
        assert_eq!(c.padding_gaps.len(), 1);
        assert!(super::parse("none").unwrap().is_none());
    }
}
