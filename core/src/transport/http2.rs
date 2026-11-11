//! Транспорты поверх HTTP/2: gRPC (gun / multi) и XHTTP (stream-one, stream-up, packet-up),
//! а также HTTP-маскировка для TCP.

use std::collections::HashMap;
use std::future::poll_fn;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use bytes::{Buf, Bytes, BytesMut};
use h2::client::SendRequest;
use h2::SendStream;
use parking_lot::Mutex;
use rand::Rng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::common::{io_err, BoxStream};
use crate::config::Profile;

const UA: &str = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36";

pub(crate) fn h2err(e: h2::Error) -> io::Error {
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

// ───────────────────────── Пул соединений ─────────────────────────

/// Больше потоков на одно TCP-соединение — сильнее взаимная блокировка при потерях.
const MAX_TUNNELS_PER_CONN: usize = 24;
/// Серверы и CDN закрывают соединение после N запросов (nginx — 1000): уходим раньше.
const MAX_REQUESTS_PER_CONN: usize = 600;
const PING_EVERY: Duration = Duration::from_secs(20);
const PING_TIMEOUT: Duration = Duration::from_secs(10);
/// Сколько проверок подряд соединение может простоять без потоков
const IDLE_TICKS: u32 = 4;

struct Pooled {
    send: SendRequest<Bytes>,
    closed: Arc<AtomicBool>,
    tunnels: Arc<AtomicUsize>,
    requests: Arc<AtomicUsize>,
}

/// Удерживает место в соединении, пока жив туннель.
pub struct TunnelGuard {
    tunnels: Arc<AtomicUsize>,
    requests: Arc<AtomicUsize>,
}

impl TunnelGuard {
    /// Учесть ещё один запрос в этом соединении; false — пора переходить на другое.
    pub fn count_request(&self) -> bool {
        self.requests.fetch_add(1, Ordering::Relaxed) + 1 < MAX_REQUESTS_PER_CONN
    }
}

impl Drop for TunnelGuard {
    fn drop(&mut self) {
        self.tunnels.fetch_sub(1, Ordering::Relaxed);
    }
}

type Pool = HashMap<String, Vec<Arc<Pooled>>>;

fn pool() -> &'static Mutex<Pool> {
    static P: OnceLock<Mutex<Pool>> = OnceLock::new();
    P.get_or_init(Default::default)
}

fn dial_locks() -> &'static Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>> {
    static L: OnceLock<Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>> = OnceLock::new();
    L.get_or_init(Default::default)
}

/// Закрыть все соединения пула (смена сети, остановка).
pub fn reset_pool() {
    for (_, list) in pool().lock().drain() {
        for c in list {
            c.closed.store(true, Ordering::Relaxed);
        }
    }
}

fn pool_key(p: &Profile) -> String {
    format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        crate::transport::network(p),
        p.address,
        p.port,
        p.security,
        p.sni,
        p.host,
        p.alpn,
        p.fingerprint,
        p.public_key,
        p.short_id,
        p.allow_insecure,
        p.pinned_cert_sha256
    )
}

fn take_pooled(key: &str) -> Option<(SendRequest<Bytes>, TunnelGuard)> {
    let mut pool = pool().lock();
    let list = pool.get_mut(key)?;
    list.retain(|c| !c.closed.load(Ordering::Relaxed));
    let c = list
        .iter()
        .filter(|c| c.requests.load(Ordering::Relaxed) < MAX_REQUESTS_PER_CONN && c.tunnels.load(Ordering::Relaxed) < MAX_TUNNELS_PER_CONN)
        .min_by_key(|c| c.tunnels.load(Ordering::Relaxed))?;
    c.tunnels.fetch_add(1, Ordering::Relaxed);
    c.requests.fetch_add(1, Ordering::Relaxed);
    Some((c.send.clone(), TunnelGuard { tunnels: c.tunnels.clone(), requests: c.requests.clone() }))
}

/// Соединение HTTP/2 для нового потока: живое из пула или новое.
pub async fn acquire<F, Fut>(key: String, dial: F) -> io::Result<(SendRequest<Bytes>, TunnelGuard)>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = io::Result<BoxStream>>,
{
    if let Some((send, guard)) = take_pooled(&key) {
        match send.ready().await {
            Ok(s) => return Ok((s, guard)),
            Err(e) => log::debug!("h2: соединение из пула не годится ({e}), открываю новое"),
        }
    }
    // одновременно стартовавшие потоки ждут одно рукопожатие, а не делают каждый своё
    let lock = dial_locks().lock().entry(key.clone()).or_default().clone();
    let _dialing = lock.lock().await;
    if let Some((send, guard)) = take_pooled(&key) {
        if let Ok(s) = send.ready().await {
            return Ok((s, guard));
        }
    }
    let stream = dial().await?;
    log::debug!("h2: новое соединение ({})", key.split('|').take(3).collect::<Vec<_>>().join(" "));
    let (send, conn) = h2::client::Builder::new()
        .initial_window_size(4 << 20)
        .initial_connection_window_size(16 << 20)
        .max_frame_size(1 << 16)
        .handshake::<_, Bytes>(stream)
        .await
        .map_err(h2err)?;
    let closed = Arc::new(AtomicBool::new(false));
    let tunnels = Arc::new(AtomicUsize::new(1));
    let mut conn = conn;
    let mut pinger = conn.ping_pong();
    let (closed2, tunnels2) = (closed.clone(), tunnels.clone());
    tokio::spawn(async move {
        let keepalive = async {
            let mut idle = 0u32;
            loop {
                tokio::time::sleep(PING_EVERY).await;
                if closed2.load(Ordering::Relaxed) {
                    return "закрыто";
                }
                if tunnels2.load(Ordering::Relaxed) == 0 {
                    idle += 1;
                    if idle >= IDLE_TICKS {
                        return "простой";
                    }
                } else {
                    idle = 0;
                }
                if let Some(pp) = pinger.as_mut() {
                    match tokio::time::timeout(PING_TIMEOUT, pp.ping(h2::Ping::opaque())).await {
                        Ok(Ok(_)) => {}
                        _ => return "сервер не отвечает на PING",
                    }
                }
            }
        };
        tokio::select! {
            r = &mut conn => {
                if let Err(e) = r {
                    log::debug!("h2 соединение закрыто: {e}");
                }
            }
            why = keepalive => log::debug!("h2 соединение закрыто: {why}"),
        }
        closed2.store(true, Ordering::Relaxed);
    });
    let send = send.ready().await.map_err(h2err)?;
    let requests = Arc::new(AtomicUsize::new(1));
    let entry = Arc::new(Pooled { send: send.clone(), closed, tunnels: tunnels.clone(), requests: requests.clone() });
    pool().lock().entry(key).or_default().push(entry);
    Ok((send, TunnelGuard { tunnels, requests }))
}

async fn acquire_for(p: &Profile) -> io::Result<(SendRequest<Bytes>, TunnelGuard)> {
    acquire(pool_key(p), || crate::transport::dial_secured(p)).await
}

/// Отправка с учётом управления потоком HTTP/2.
pub(crate) async fn send_all(tx: &mut SendStream<Bytes>, mut data: Bytes) -> io::Result<()> {
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
async fn pump_response<F>(
    resp: h2::client::ResponseFuture,
    mut out: tokio::io::WriteHalf<tokio::io::DuplexStream>,
    mut f: F,
    _guard: TunnelGuard,
) where
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
        log::warn!("HTTP/2: {e}");
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

/// `url.PathEscape` из Go: не кодируются буквы, цифры, `-_.~` и `$&+:=@`.
fn go_path_escape(s: &str) -> String {
    const SET: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
        .remove(b'-')
        .remove(b'_')
        .remove(b'.')
        .remove(b'~')
        .remove(b'$')
        .remove(b'&')
        .remove(b'+')
        .remove(b':')
        .remove(b'=')
        .remove(b'@');
    percent_encoding::utf8_percent_encode(s, SET).to_string()
}

/// Путь gRPC-запроса — точно как в Xray (`transport/internet/grpc/config.go`):
/// * "имя" → `/имя/Tun` (`/имя/TunMulti`), имя кодируется как `url.PathEscape`;
/// * "/a/b/Tun1|Tun2" (новый формат) → `/a/b/Tun1` (`/a/b/Tun2` для multi).
fn grpc_path(service: &str, multi: bool) -> String {
    let s = service.trim();
    if !s.starts_with('/') {
        return format!("/{}/{}", go_path_escape(s), if multi { "TunMulti" } else { "Tun" });
    }
    let last = s.rfind('/').unwrap_or(0);
    let service_name = s[1..last.max(1)].split('/').map(go_path_escape).collect::<Vec<_>>().join("/");
    let ending = &s[last + 1..];
    let mut names = ending.split('|');
    let tun = names.next().unwrap_or("");
    let stream = if multi { names.next().unwrap_or(tun) } else { tun };
    format!("/{service_name}/{stream}")
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

pub async fn grpc(p: &Profile) -> io::Result<BoxStream> {
    let (mut send, guard) = acquire_for(p).await?;
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
    tokio::spawn(pump_response(resp, bw, move |chunk, out| dec.feed(chunk, out), guard));
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

pub async fn xhttp(p: &Profile) -> io::Result<BoxStream> {
    let (send, guard) = acquire_for(p).await?;
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
        tokio::spawn(pump_response(resp, bw, |c, out| out.extend_from_slice(c), guard));
        return Ok(Box::new(a));
    }

    let session = uuid::Uuid::new_v4().to_string();
    let url = format!("{base}{session}");
    // загрузка (stream-down)
    let mut s = send.clone();
    let (resp, mut down_tx) = s.send_request(stream_req("GET", &url, false)?, true).map_err(h2err)?;
    let _ = &mut down_tx;
    tokio::spawn(pump_response(resp, bw, |c, out| out.extend_from_slice(c), guard));

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
    let profile = p.clone();
    tokio::spawn(async move {
        let mut br = br;
        let mut send = send;
        let mut up_guard: Option<TunnelGuard> = None;
        let mut fresh = true;
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
            // соединение могло закрыться или исчерпать лимит запросов — берём другое из пула
            let usable = fresh || up_guard.as_ref().map(|g| g.count_request()).unwrap_or(true);
            fresh = false;
            let ready = if usable { send.clone().ready().await.map_err(|_| ()) } else { Err(()) };
            let mut s = match ready {
                Ok(s) => s,
                Err(()) => match acquire_for(&profile).await {
                    Ok((s, g)) => {
                        send = s.clone();
                        up_guard = Some(g);
                        fresh = true;
                        s
                    }
                    Err(e) => {
                        log::warn!("XHTTP: {e}");
                        break;
                    }
                },
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
        assert_eq!(grpc_path("mysvc", true), "/mysvc/TunMulti");
    }

    #[test]
    fn grpc_path_like_xray() {
        // символы, которые Go не кодирует в PathEscape, должны остаться как есть
        assert_eq!(grpc_path("my-svc_v2.grpc~x", false), "/my-svc_v2.grpc~x/Tun");
        assert_eq!(grpc_path("a b/c", false), "/a%20b%2Fc/Tun");
        // новый формат: "/сервис/Tun|TunMulti"
        assert_eq!(grpc_path("/my/sample/path1|path2", false), "/my/sample/path1");
        assert_eq!(grpc_path("/my/sample/path1|path2", true), "/my/sample/path2");
        assert_eq!(grpc_path("/my/sample/path1", true), "/my/sample/path1");
    }
}
