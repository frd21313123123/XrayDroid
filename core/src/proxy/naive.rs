//! NaiveProxy: HTTP/2 CONNECT поверх TLS с отпечатком Chrome и паддингом первых кадров.
//! Соединение HTTP/2 общее для всех потоков — как у браузера.

use std::io;

use base64::Engine;
use bytes::{Buf, Bytes, BytesMut};
use rand::Rng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::common::{io_err, Address, BoxStream, Host};
use crate::config::Profile;
use crate::transport::{self, http2};

/// Сколько первых записей в каждую сторону идут с паддингом.
const PADDED: usize = 8;

fn padding_header() -> String {
    let mut rng = rand::thread_rng();
    let n = rng.gen_range(30..62);
    let symbols = b"!#$()+<>?@[]^`{}";
    (0..n).map(|i| if i < 16 { symbols[rng.gen_range(0..symbols.len())] as char } else { '~' }).collect()
}

/// Снимает паддинг с первых кадров: [длина u16][паддинг u8][данные][нули].
#[derive(Default)]
struct Unpad {
    frames: usize,
    buf: BytesMut,
}

impl Unpad {
    fn feed(&mut self, data: &[u8], out: &mut Vec<u8>) {
        if self.frames >= PADDED && self.buf.is_empty() {
            out.extend_from_slice(data);
            return;
        }
        self.buf.extend_from_slice(data);
        while self.frames < PADDED {
            if self.buf.len() < 3 {
                return;
            }
            let len = u16::from_be_bytes([self.buf[0], self.buf[1]]) as usize;
            let pad = self.buf[2] as usize;
            if self.buf.len() < 3 + len + pad {
                return;
            }
            self.buf.advance(3);
            out.extend_from_slice(&self.buf[..len]);
            self.buf.advance(len + pad);
            self.frames += 1;
        }
        out.extend_from_slice(&self.buf);
        self.buf.clear();
    }
}

fn pad(data: &[u8]) -> Bytes {
    let p = rand::thread_rng().gen_range(0..256usize);
    let mut v = Vec::with_capacity(3 + data.len() + p);
    v.extend_from_slice(&(data.len() as u16).to_be_bytes());
    v.push(p as u8);
    v.extend_from_slice(data);
    v.resize(v.len() + p, 0);
    Bytes::from(v)
}

pub async fn tcp(p: &Profile, app: BoxStream, dest: &Address) -> io::Result<()> {
    // сервер naive ждёт браузер: всегда ClientHello как у Chrome
    let mut prof = p.clone();
    if prof.fingerprint.is_empty() {
        prof.fingerprint = "chrome".into();
    }
    prof.security = "tls".into();
    let key = format!("naive|{}|{}|{}|{}|{}|{}", p.address, p.port, p.sni, p.username, p.allow_insecure, p.pinned_cert_sha256);
    let (mut send, guard) = http2::acquire(key, || async {
        let tcp = transport::dialer::connect_for_tls(&transport::server_addr(&prof)).await?;
        transport::tls_for_profile(tcp, &prof, "h2").await
    })
    .await?;

    let target = match &dest.host {
        Host::Domain(d) => format!("{d}:{}", dest.port),
        _ => dest.to_string(),
    };
    let mut req = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(target.as_str())
        .header("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
        .header("padding", padding_header());
    if !p.username.is_empty() || !p.id_or_password.is_empty() {
        let cred = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", p.username, p.id_or_password));
        req = req.header("proxy-authorization", format!("Basic {cred}"));
    }
    let req = req.body(()).map_err(|e| io_err(e.to_string()))?;
    let (resp, mut tx) = send.send_request(req, false).map_err(http2::h2err)?;
    let resp = tokio::time::timeout(transport::CONNECT_TIMEOUT, resp)
        .await
        .map_err(|_| io_err("Naive: сервер не отвечает"))?
        .map_err(http2::h2err)?;
    match resp.status().as_u16() {
        200 => {}
        407 => return Err(io_err("Naive: неверный логин или пароль")),
        code => return Err(io_err(format!("Naive: сервер ответил HTTP {code}"))),
    }
    // сервер с поддержкой паддинга отвечает заголовком padding
    let padded = resp.headers().contains_key("padding");
    let mut body = resp.into_body();
    let (mut ar, mut aw) = tokio::io::split(app);

    let up = async move {
        let mut buf = vec![0u8; 32 * 1024];
        let mut sent = 0usize;
        loop {
            let n = ar.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            let data = if padded && sent < PADDED {
                sent += 1;
                pad(&buf[..n])
            } else {
                Bytes::copy_from_slice(&buf[..n])
            };
            http2::send_all(&mut tx, data).await?;
        }
        let _ = tx.send_data(Bytes::new(), true);
        Ok::<_, io::Error>(())
    };
    let down = async move {
        let _guard = guard;
        let mut unpad = Unpad { frames: if padded { 0 } else { PADDED }, buf: BytesMut::new() };
        let mut out = Vec::new();
        while let Some(chunk) = body.data().await {
            let chunk = chunk.map_err(http2::h2err)?;
            let _ = body.flow_control().release_capacity(chunk.len());
            out.clear();
            unpad.feed(&chunk, &mut out);
            if !out.is_empty() {
                aw.write_all(&out).await?;
            }
        }
        let _ = aw.shutdown().await;
        Ok::<_, io::Error>(())
    };
    crate::common::join_halves(up, down).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding_roundtrip() {
        let mut wire = Vec::new();
        let mut expect = Vec::new();
        for i in 0..PADDED {
            let d = vec![i as u8; 10 + i * 37];
            wire.extend_from_slice(&pad(&d));
            expect.extend_from_slice(&d);
        }
        wire.extend_from_slice(b"plain tail");
        expect.extend_from_slice(b"plain tail");
        let mut u = Unpad::default();
        let mut out = Vec::new();
        for c in wire.chunks(7) {
            u.feed(c, &mut out);
        }
        assert_eq!(out, expect);
        let h = padding_header();
        assert!((30..62).contains(&h.len()));
    }
}
