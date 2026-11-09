//! Транспорты поверх HTTP/2: gRPC (gun / multi) и XHTTP (stream-one, stream-up, packet-up),
//! а также HTTP-маскировка для TCP.

use std::future::poll_fn;
use std::io;

use bytes::{Buf, Bytes, BytesMut};
use h2::client::SendRequest;
use h2::SendStream;
use rand::Rng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::common::{io_err, BoxStream};
use crate::config::Profile;

const UA: &str = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36";

fn h2err(e: h2::Error) -> io::Error {
    io_err(format!("HTTP/2: {e}"))
}

pub fn authority(p: &Profile) -> String {
    if !p.host.trim().is_empty() {
        p.host.split(',').next().unwrap_or("").trim().to_string()
    } else if !p.sni.is_empty() {
        p.sni.clone()
    } else {
        p.address.clone()
    }
}

fn scheme(p: &Profile) -> &'static str {
    if p.security == "tls" || p.security == "reality" {
        "https"
    } else {
        "http"
    }
}

async fn connect(stream: BoxStream) -> io::Result<SendRequest<Bytes>> {
    let (send, conn) = h2::client::Builder::new()
        .initial_window_size(4 << 20)
        .initial_connection_window_size(8 << 20)
        .max_frame_size(1 << 16)
        .handshake::<_, Bytes>(stream)
        .await
        .map_err(h2err)?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            log::debug!("h2 соединение закрыто: {e}");
        }
    });
    send.ready().await.map_err(h2err)
}

/// Отправка с учётом управления потоком HTTP/2.
async fn send_all(tx: &mut SendStream<Bytes>, mut data: Bytes) -> io::Result<()> {
    while !data.is_empty() {
        tx.reserve_capacity(data.len());
        let cap = match poll_fn(|cx| tx.poll_capacity(cx)).await {
            Some(r) => r.map_err(h2err)?,
            None => return Err(io_err("HTTP/2: поток закрыт")),
        };
        if cap == 0 {
            continue;
        }
        let chunk = data.split_to(cap.min(data.len()));
        tx.send_data(chunk, false).map_err(h2err)?;
    }
    Ok(())
}

fn request(method: &str, uri: &str) -> http::request::Builder {
    http::Request::builder().method(method).uri(uri).header("user-agent", UA)
}

/// Чтение тела ответа и передача (с преобразованием) в канал.
async fn pump_response<F>(resp: h2::client::ResponseFuture, mut out: tokio::io::WriteHalf<tokio::io::DuplexStream>, mut f: F)
where
    F: FnMut(&[u8], &mut Vec<u8>),
{
    let r: io::Result<()> = async {
        let resp = resp.await.map_err(h2err)?;
        if resp.status() != http::StatusCode::OK {
            return Err(io_err(format!("сервер ответил HTTP {}", resp.status())));
        }
        let mut body = resp.into_body();
        let mut decoded = Vec::new();
        while let Some(chunk) = body.data().await {
            let chunk = chunk.map_err(h2err)?;
            let _ = body.flow_control().release_capacity(chunk.len());
            decoded.clear();
            f(&chunk, &mut decoded);
            if !decoded.is_empty() {
                out.write_all(&decoded).await?;
            }
        }
        Ok(())
    }
    .await;
    if let Err(e) = r {
        log::debug!("{e}");
    }
    let _ = out.shutdown().await;
}

/// Чтение из канала и отправка в тело запроса.
async fn pump_request<F>(mut input: tokio::io::ReadHalf<tokio::io::DuplexStream>, mut tx: SendStream<Bytes>, mut f: F)
where
    F: FnMut(&[u8]) -> Bytes,
{
    let mut buf = vec![0u8; 32 * 1024];
    loop {
        let n = match input.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        if send_all(&mut tx, f(&buf[..n])).await.is_err() {
            return;
        }
    }
    let _ = tx.send_data(Bytes::new(), true);
}

// ───────────────────────── gRPC ─────────────────────────

fn grpc_path(service: &str, multi: bool) -> String {
    let s = service.trim();
    if s.starts_with('/') {
        // новый формат Xray: "/путь/Tun|TunMulti"
        let mut parts = s.splitn(2, '|');
        let tun = parts.next().unwrap_or("/");
        let multi_p = parts.next().unwrap_or(tun);
        return if multi { multi_p.to_string() } else { tun.to_string() };
    }
    let name: String = percent_encoding::utf8_percent_encode(s, percent_encoding::NON_ALPHANUMERIC).to_string();
    format!("/{}/{}", name, if multi { "TunMulti" } else { "Tun" })
}

fn varint(mut v: usize, out: &mut Vec<u8>) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

fn grpc_encode(data: &[u8]) -> Bytes {
    let mut msg = Vec::with_capacity(data.len() + 16);
    msg.push(0x0a);
    varint(data.len(), &mut msg);
    msg.extend_from_slice(data);
    let mut out = Vec::with_capacity(msg.len() + 5);
    out.push(0);
    out.extend_from_slice(&(msg.len() as u32).to_be_bytes());
    out.extend_from_slice(&msg);
    Bytes::from(out)
}

/// Разбор потока gRPC-сообщений Hunk/MultiHunk (поле 1 bytes, повторяемое).
#[derive(Default)]
struct GrpcDecoder {
    buf: BytesMut,
}

impl GrpcDecoder {
    fn feed(&mut self, data: &[u8], out: &mut Vec<u8>) {
        self.buf.extend_from_slice(data);
        loop {
            if self.buf.len() < 5 {
                return;
            }
            let len = u32::from_be_bytes([self.buf[1], self.buf[2], self.buf[3], self.buf[4]]) as usize;
            if self.buf.len() < 5 + len {
                return;
            }
            self.buf.advance(5);
            let msg = self.buf.split_to(len);
            let mut p = 0;
            let rd = |p: &mut usize| -> Option<usize> {
                let mut v = 0usize;
                let mut shift = 0;
                loop {
                    let b = *msg.get(*p)?;
                    *p += 1;
                    v |= ((b & 0x7f) as usize) << shift;
                    if b & 0x80 == 0 {
                        return Some(v);
                    }
                    shift += 7;
                }
            };
            while p < msg.len() {
                let Some(tag) = rd(&mut p) else { break };
                match tag & 7 {
                    2 => {
                        let Some(l) = rd(&mut p) else { break };
                        if tag >> 3 == 1 {
                            if let Some(d) = msg.get(p..p + l) {
                                out.extend_from_slice(d);
                            }
                        }
                        p += l;
                    }
                    0 => {
                        let _ = rd(&mut p);
                    }
                    _ => break,
                }
            }
        }
    }
}

pub async fn grpc(stream: BoxStream, p: &Profile) -> io::Result<BoxStream> {
    let mut send = connect(stream).await?;
    let multi = p.header_type == "multi";
    let uri = format!("{}://{}{}", scheme(p), authority(p), grpc_path(&p.path, multi));
    let req = request("POST", &uri)
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(())
        .map_err(|e| io_err(e.to_string()))?;
    let (resp, tx) = send.send_request(req, false).map_err(h2err)?;
    let (a, b) = tokio::io::duplex(256 * 1024);
    let (br, bw) = tokio::io::split(b);
    tokio::spawn(pump_request(br, tx, grpc_encode));
    let mut dec = GrpcDecoder::default();
    tokio::spawn(pump_response(resp, bw, move |chunk, out| dec.feed(chunk, out)));
    Ok(Box::new(a))
}

// ───────────────────────── XHTTP ─────────────────────────

fn xhttp_base_path(path: &str) -> String {
    let p = path.split('?').next().unwrap_or("");
    let mut p = if p.starts_with('/') { p.to_string() } else { format!("/{p}") };
    if !p.ends_with('/') {
        p.push('/');
    }
    p
}

fn referer_padding(url: &str) -> String {
    let n = rand::thread_rng().gen_range(100..=1000);
    format!("{}?x_padding={}", url.split('?').next().unwrap_or(url), "X".repeat(n))
}

pub fn xhttp_mode(p: &Profile) -> &'static str {
    match p.header_type.as_str() {
        "stream-one" => "stream-one",
        "stream-up" => "stream-up",
        "packet-up" => "packet-up",
        _ => {
            if p.security == "reality" {
                "stream-one"
            } else {
                "packet-up"
            }
        }
    }
}

pub async fn xhttp(stream: BoxStream, p: &Profile) -> io::Result<BoxStream> {
    let send = connect(stream).await?;
    let base = format!("{}://{}{}", scheme(p), authority(p), xhttp_base_path(&p.path));
    let mode = xhttp_mode(p);
    let (a, b) = tokio::io::duplex(256 * 1024);
    let (br, bw) = tokio::io::split(b);

    let stream_req = |method: &str, url: &str, body: bool| {
        let mut r = request(method, url).header("referer", referer_padding(url));
        if body {
            r = r.header("content-type", "application/grpc");
        }
        r.body(()).map_err(|e| io_err(e.to_string()))
    };

    if mode == "stream-one" {
        let mut s = send.clone();
        let (resp, tx) = s.send_request(stream_req("POST", &base, true)?, false).map_err(h2err)?;
        tokio::spawn(pump_request(br, tx, Bytes::copy_from_slice));
        tokio::spawn(pump_response(resp, bw, |c, out| out.extend_from_slice(c)));
        return Ok(Box::new(a));
    }

    let session = uuid::Uuid::new_v4().to_string();
    let url = format!("{base}{session}");
    // загрузка (stream-down)
    let mut s = send.clone();
    let (resp, mut down_tx) = s.send_request(stream_req("GET", &url, false)?, true).map_err(h2err)?;
    let _ = &mut down_tx;
    tokio::spawn(pump_response(resp, bw, |c, out| out.extend_from_slice(c)));

    if mode == "stream-up" {
        let mut s = send.clone();
        s = s.ready().await.map_err(h2err)?;
        let (resp, tx) = s.send_request(stream_req("POST", &url, true)?, false).map_err(h2err)?;
        tokio::spawn(pump_request(br, tx, Bytes::copy_from_slice));
        tokio::spawn(async move {
            let _ = resp.await;
        });
        return Ok(Box::new(a));
    }

    // packet-up: каждый кусок — отдельный POST /path/session/seq
    tokio::spawn(async move {
        let mut br = br;
        let mut seq: u64 = 0;
        let mut buf = vec![0u8; 1_000_000];
        let mut last = tokio::time::Instant::now() - std::time::Duration::from_secs(1);
        loop {
            let mut n = match br.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            // пока выдерживаем интервал между POST, докапливаем данные в тот же запрос
            let deadline = last + std::time::Duration::from_millis(30);
            let mut eof = false;
            while n < buf.len() {
                match tokio::time::timeout_at(deadline, br.read(&mut buf[n..])).await {
                    Ok(Ok(0)) | Ok(Err(_)) => {
                        eof = true;
                        break;
                    }
                    Ok(Ok(k)) => n += k,
                    Err(_) => break,
                }
            }
            last = tokio::time::Instant::now();
            let u = format!("{url}/{seq}");
            seq += 1;
            let req = match request("POST", &u).header("referer", referer_padding(&u)).body(()) {
                Ok(r) => r,
                Err(_) => break,
            };
            let mut s = match send.clone().ready().await {
                Ok(s) => s,
                Err(_) => break,
            };
            let (resp, mut tx) = match s.send_request(req, false) {
                Ok(x) => x,
                Err(_) => break,
            };
            if send_all(&mut tx, Bytes::copy_from_slice(&buf[..n])).await.is_err() {
                break;
            }
            let _ = tx.send_data(Bytes::new(), true);
            let stop = eof;
            tokio::spawn(async move {
                match resp.await {
                    Ok(r) if r.status() != http::StatusCode::OK => log::debug!("XHTTP POST: HTTP {}", r.status()),
                    Err(e) => log::debug!("XHTTP POST: {e}"),
                    _ => {}
                }
            });
            if stop {
                break;
            }
        }
    });
    Ok(Box::new(a))
}

// ───────────────────────── TCP + HTTP-маскировка ─────────────────────────

pub async fn http_obfs(stream: BoxStream, p: &Profile) -> io::Result<BoxStream> {
    let path = p.path.split(',').next().map(|s| s.trim()).filter(|s| !s.is_empty()).unwrap_or("/").to_string();
    let host = if p.host.is_empty() { p.address.clone() } else { p.host.split(',').next().unwrap_or("").trim().to_string() };
    let header = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {UA}\r\nAccept-Encoding: gzip, deflate\r\nConnection: keep-alive\r\nPragma: no-cache\r\n\r\n"
    );
    let (a, b) = tokio::io::duplex(128 * 1024);
    let (mut br, mut bw) = tokio::io::split(b);
    let (mut sr, mut sw) = tokio::io::split(stream);
    tokio::spawn(async move {
        let mut buf = vec![0u8; 32 * 1024];
        let mut first = true;
        loop {
            let n = match br.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let r = if first {
                first = false;
                let mut v = header.clone().into_bytes();
                v.extend_from_slice(&buf[..n]);
                sw.write_all(&v).await
            } else {
                sw.write_all(&buf[..n]).await
            };
            if r.is_err() {
                break;
            }
        }
        let _ = sw.shutdown().await;
    });
    tokio::spawn(async move {
        let mut head = Vec::new();
        let mut b = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            match sr.read(&mut b).await {
                Ok(1) => head.push(b[0]),
                _ => {
                    let _ = bw.shutdown().await;
                    return;
                }
            }
            if head.len() > 16384 {
                let _ = bw.shutdown().await;
                return;
            }
        }
        let _ = tokio::io::copy(&mut sr, &mut bw).await;
        let _ = bw.shutdown().await;
    });
    Ok(Box::new(a))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grpc_roundtrip() {
        let mut enc = grpc_encode(b"hello").to_vec();
        enc.extend_from_slice(&grpc_encode(&vec![7u8; 300]));
        let mut d = GrpcDecoder::default();
        let mut out = Vec::new();
        for c in enc.chunks(3) {
            d.feed(c, &mut out);
        }
        assert_eq!(&out[..5], b"hello");
        assert_eq!(out.len(), 305);
        assert_eq!(grpc_path("mysvc", false), "/mysvc/Tun");
        assert_eq!(grpc_path("/a/b|c", true), "c");
    }
}
