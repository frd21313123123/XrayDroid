//! Установка TCP-соединений: кэш DNS, параллельные попытки по всем адресам сервера
//! (Happy Eyeballs), TCP keepalive и фрагментация TLS ClientHello.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::OnceLock;
use std::task::{ready, Context, Poll};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use crate::common::{io_err, Address, BoxStream, Host};
use crate::config::Settings;

// ───────────────────────── DNS ─────────────────────────

/// Свежая запись используется без запроса; устаревшая — только если резолвер не ответил
/// (смена сети, DNS оператора недоступен): лучше старый адрес, чем обрыв.
const DNS_FRESH: Duration = Duration::from_secs(300);
const DNS_STALE: Duration = Duration::from_secs(24 * 3600);
const DNS_TIMEOUT: Duration = Duration::from_secs(5);

struct DnsEntry {
    ips: Vec<IpAddr>,
    at: Instant,
}

fn dns_cache() -> &'static Mutex<HashMap<String, DnsEntry>> {
    static C: OnceLock<Mutex<HashMap<String, DnsEntry>>> = OnceLock::new();
    C.get_or_init(Default::default)
}

/// Адрес, по которому в последний раз удалось подключиться к хосту: с него и начинаем.
fn last_good() -> &'static Mutex<HashMap<String, IpAddr>> {
    static C: OnceLock<Mutex<HashMap<String, IpAddr>>> = OnceLock::new();
    C.get_or_init(Default::default)
}

/// IPv4 и IPv6 вперемешку, начиная с IPv4 (в мобильных сетях IPv6 чаще сломан).
fn interleave(ips: Vec<IpAddr>) -> Vec<IpAddr> {
    let (v4, v6): (Vec<IpAddr>, Vec<IpAddr>) = ips.into_iter().partition(|i| i.is_ipv4());
    let mut out = Vec::with_capacity(v4.len() + v6.len());
    let (mut a, mut b) = (v4.into_iter(), v6.into_iter());
    loop {
        match (a.next(), b.next()) {
            (None, None) => break,
            (x, y) => {
                out.extend(x);
                out.extend(y);
            }
        }
    }
    out
}

/// Все адреса хоста в порядке предпочтения.
pub async fn resolve_host(host: &str) -> io::Result<Vec<IpAddr>> {
    let key = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if let Ok(ip) = key.trim_start_matches('[').trim_end_matches(']').parse::<IpAddr>() {
        return Ok(vec![ip]);
    }
    let cached = dns_cache().lock().get(&key).map(|e| (e.ips.clone(), e.at.elapsed()));
    if let Some((ips, age)) = &cached {
        if *age < DNS_FRESH {
            return Ok(order(&key, ips.clone()));
        }
    }
    let looked = tokio::time::timeout(DNS_TIMEOUT, tokio::net::lookup_host((key.as_str(), 0))).await;
    let fresh: Option<Vec<IpAddr>> = match looked {
        Ok(Ok(it)) => {
            let mut v: Vec<IpAddr> = Vec::new();
            for sa in it {
                if !v.contains(&sa.ip()) {
                    v.push(sa.ip());
                }
            }
            (!v.is_empty()).then_some(v)
        }
        _ => None,
    };
    match (fresh, cached) {
        (Some(ips), _) => {
            let ips = interleave(ips);
            let mut c = dns_cache().lock();
            if c.len() > 2048 {
                c.retain(|_, e| e.at.elapsed() < DNS_FRESH);
            }
            c.insert(key.clone(), DnsEntry { ips: ips.clone(), at: Instant::now() });
            drop(c);
            Ok(order(&key, ips))
        }
        (None, Some((ips, age))) if age < DNS_STALE => {
            log::debug!("DNS {key}: резолвер не ответил, беру адрес из кэша");
            Ok(order(&key, ips))
        }
        _ => Err(io::Error::new(io::ErrorKind::NotFound, format!("не удалось определить адрес {host}"))),
    }
}

fn order(key: &str, mut ips: Vec<IpAddr>) -> Vec<IpAddr> {
    if let Some(good) = last_good().lock().get(key) {
        if let Some(i) = ips.iter().position(|x| x == good) {
            let g = ips.remove(i);
            ips.insert(0, g);
        }
    }
    ips
}

fn remember_good(host: &str, ip: IpAddr) {
    let mut m = last_good().lock();
    if m.len() > 2048 {
        m.clear();
    }
    m.insert(host.trim().trim_end_matches('.').to_ascii_lowercase(), ip);
}

/// Забыть результаты DNS (смена сети).
pub fn flush_dns() {
    dns_cache().lock().clear();
    last_good().lock().clear();
}

pub async fn resolve(addr: &Address) -> io::Result<SocketAddr> {
    match &addr.host {
        Host::Ip(ip) => Ok(SocketAddr::new(*ip, addr.port)),
        Host::Domain(d) => Ok(SocketAddr::new(resolve_host(d).await?[0], addr.port)),
    }
}

// ───────────────────────── TCP ─────────────────────────

/// Пауза перед попыткой по следующему адресу (RFC 8305).
const ATTEMPT_DELAY: Duration = Duration::from_millis(250);

fn tune(s: &TcpStream) {
    s.set_nodelay(true).ok();
    let ka = socket2::TcpKeepalive::new().with_time(Duration::from_secs(45)).with_interval(Duration::from_secs(15));
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let ka = ka.with_retries(4);
    socket2::SockRef::from(s).set_tcp_keepalive(&ka).ok();
}

/// TCP-соединение: если у хоста несколько адресов, пробуем их по очереди с небольшим
/// сдвигом и берём первое установившееся.
pub async fn connect(addr: &Address) -> io::Result<TcpStream> {
    let (host, ips) = match &addr.host {
        Host::Ip(ip) => (None, vec![*ip]),
        Host::Domain(d) => (Some(d.as_str()), resolve_host(d).await?),
    };
    let port = addr.port;
    if ips.len() == 1 {
        let s = TcpStream::connect(SocketAddr::new(ips[0], port)).await?;
        tune(&s);
        return Ok(s);
    }
    let mut set = tokio::task::JoinSet::new();
    let mut pending = ips.into_iter().take(6);
    let mut last_err: Option<io::Error> = None;
    let mut exhausted = false;
    loop {
        if !exhausted {
            match pending.next() {
                Some(ip) => {
                    set.spawn(async move { (ip, TcpStream::connect(SocketAddr::new(ip, port)).await) });
                }
                None => exhausted = true,
            }
        }
        if set.is_empty() {
            break;
        }
        let joined = if exhausted {
            set.join_next().await
        } else {
            match tokio::time::timeout(ATTEMPT_DELAY, set.join_next()).await {
                Ok(j) => j,
                Err(_) => continue,
            }
        };
        match joined {
            Some(Ok((ip, Ok(s)))) => {
                tune(&s);
                if let Some(h) = host {
                    remember_good(h, ip);
                }
                return Ok(s);
            }
            Some(Ok((_, Err(e)))) => last_err = Some(e),
            Some(Err(_)) | None => {}
        }
    }
    Err(last_err.unwrap_or_else(|| io_err(format!("не удалось подключиться к {addr}"))))
}

// ───────────────────────── Фрагментация ClientHello ─────────────────────────

static FRAG_ON: AtomicBool = AtomicBool::new(false);
static FRAG_LEN_MIN: AtomicU32 = AtomicU32::new(100);
static FRAG_LEN_MAX: AtomicU32 = AtomicU32::new(200);
static FRAG_GAP_MIN: AtomicU32 = AtomicU32::new(10);
static FRAG_GAP_MAX: AtomicU32 = AtomicU32::new(20);

/// "100-200" → (100, 200); "50" → (50, 50).
pub fn parse_range(s: &str, default: (u32, u32)) -> (u32, u32) {
    let s = s.trim();
    let (a, b) = s.split_once('-').unwrap_or((s, s));
    match (a.trim().parse::<u32>(), b.trim().parse::<u32>()) {
        (Ok(a), Ok(b)) if a <= b => (a, b),
        (Ok(a), Ok(b)) => (b, a),
        _ => default,
    }
}

/// Применяет сетевые настройки, общие для всех исходящих соединений процесса.
pub fn apply_settings(s: &Settings) {
    let (lmin, lmax) = parse_range(&s.fragment_length, (100, 200));
    let (gmin, gmax) = parse_range(&s.fragment_interval, (10, 20));
    FRAG_LEN_MIN.store(lmin.clamp(1, 16000), Ordering::Relaxed);
    FRAG_LEN_MAX.store(lmax.clamp(1, 16000), Ordering::Relaxed);
    FRAG_GAP_MIN.store(gmin.min(1000), Ordering::Relaxed);
    FRAG_GAP_MAX.store(gmax.min(1000), Ordering::Relaxed);
    FRAG_ON.store(s.fragment, Ordering::Relaxed);
}

/// TCP до сервера под TLS/REALITY: при включённой фрагментации ClientHello уходит
/// несколькими TLS-записями в отдельных сегментах — DPI, который не собирает их, не видит SNI.
pub async fn connect_for_tls(addr: &Address) -> io::Result<BoxStream> {
    let tcp = super::connect_tcp(addr).await?;
    Ok(wrap_for_tls(tcp))
}

pub fn wrap_for_tls(tcp: TcpStream) -> BoxStream {
    if FRAG_ON.load(Ordering::Relaxed) {
        Box::new(FragmentStream::new(tcp))
    } else {
        Box::new(tcp)
    }
}

/// Делит первую TLS-запись с рукопожатием на записи случайной длины.
/// Хвост (если в буфере было что-то ещё) идёт последним куском как есть.
pub fn split_hello(buf: &[u8], min: usize, max: usize) -> Option<Vec<Vec<u8>>> {
    if buf.len() < 6 || buf[0] != 0x16 || buf[1] != 0x03 {
        return None;
    }
    let len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if len == 0 || buf.len() < 5 + len {
        return None;
    }
    let body = &buf[5..5 + len];
    let (min, max) = (min.max(1), max.max(min.max(1)));
    let mut out = Vec::new();
    let mut pos = 0;
    let mut rng = rand::thread_rng();
    while pos < body.len() {
        let n = rng.gen_range(min..=max).min(body.len() - pos);
        let mut rec = Vec::with_capacity(5 + n);
        rec.extend_from_slice(&buf[..3]);
        rec.extend_from_slice(&(n as u16).to_be_bytes());
        rec.extend_from_slice(&body[pos..pos + n]);
        out.push(rec);
        pos += n;
    }
    if buf.len() > 5 + len {
        out.push(buf[5 + len..].to_vec());
    }
    Some(out)
}

enum FragState {
    /// Ждём первую запись приложения
    Fresh,
    /// Отправляем куски; `accepted` — сколько байт исходного буфера уже «принято»
    Sending { chunks: std::collections::VecDeque<Vec<u8>>, off: usize, sleep: Option<Pin<Box<tokio::time::Sleep>>>, accepted: usize },
    Done,
}

pub struct FragmentStream<S> {
    inner: S,
    state: FragState,
}

impl<S> FragmentStream<S> {
    pub fn new(inner: S) -> Self {
        Self { inner, state: FragState::Fresh }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for FragmentStream<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for FragmentStream<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if let FragState::Fresh = this.state {
            let (min, max) = (FRAG_LEN_MIN.load(Ordering::Relaxed) as usize, FRAG_LEN_MAX.load(Ordering::Relaxed) as usize);
            match split_hello(buf, min, max) {
                Some(chunks) if chunks.len() > 1 => {
                    this.state = FragState::Sending { chunks: chunks.into(), off: 0, sleep: None, accepted: buf.len() };
                }
                _ => this.state = FragState::Done,
            }
        }
        loop {
            match &mut this.state {
                FragState::Done | FragState::Fresh => return Pin::new(&mut this.inner).poll_write(cx, buf),
                FragState::Sending { chunks, off, sleep, accepted } => {
                    if let Some(s) = sleep {
                        ready!(s.as_mut().poll(cx));
                        *sleep = None;
                    }
                    let Some(front) = chunks.front() else {
                        let n = *accepted;
                        this.state = FragState::Done;
                        return Poll::Ready(Ok(n));
                    };
                    let n = ready!(Pin::new(&mut this.inner).poll_write(cx, &front[*off..]))?;
                    if n == 0 {
                        return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                    }
                    *off += n;
                    if *off >= front.len() {
                        chunks.pop_front();
                        *off = 0;
                        if !chunks.is_empty() {
                            let (a, b) = (FRAG_GAP_MIN.load(Ordering::Relaxed), FRAG_GAP_MAX.load(Ordering::Relaxed));
                            let ms = rand::thread_rng().gen_range(a..=b.max(a));
                            if ms > 0 {
                                *sleep = Some(Box::pin(tokio::time::sleep(Duration::from_millis(ms as u64))));
                            }
                        }
                    }
                }
            }
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_split_keeps_bytes() {
        let body: Vec<u8> = (0..1000u32).map(|i| i as u8).collect();
        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(body.len() as u16).to_be_bytes());
        rec.extend_from_slice(&body);
        rec.extend_from_slice(b"tail");
        let parts = split_hello(&rec, 100, 200).unwrap();
        assert!(parts.len() >= 6);
        let mut joined = Vec::new();
        for p in &parts[..parts.len() - 1] {
            assert_eq!(&p[..3], &[0x16, 0x03, 0x01]);
            let l = u16::from_be_bytes([p[3], p[4]]) as usize;
            assert_eq!(l, p.len() - 5);
            assert!((1..=200).contains(&l));
            joined.extend_from_slice(&p[5..]);
        }
        assert_eq!(joined, body);
        assert_eq!(parts.last().unwrap(), b"tail");
        // не рукопожатие — не трогаем
        assert!(split_hello(b"GET / HTTP/1.1\r\n", 100, 200).is_none());
    }

    #[test]
    fn ranges() {
        assert_eq!(parse_range("100-200", (1, 2)), (100, 200));
        assert_eq!(parse_range(" 50 ", (1, 2)), (50, 50));
        assert_eq!(parse_range("x", (1, 2)), (1, 2));
        assert_eq!(parse_range("30-10", (1, 2)), (10, 30));
    }

    #[test]
    fn v4_v6_interleaved() {
        let ips: Vec<IpAddr> = ["2001:db8::1", "1.1.1.1", "2001:db8::2", "2.2.2.2"].iter().map(|s| s.parse().unwrap()).collect();
        let o = interleave(ips);
        assert_eq!(o[0].to_string(), "1.1.1.1");
        assert_eq!(o[1].to_string(), "2001:db8::1");
        assert_eq!(o[2].to_string(), "2.2.2.2");
    }

    #[tokio::test]
    async fn fragment_stream_writes_everything() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        FRAG_GAP_MIN.store(0, Ordering::Relaxed);
        FRAG_GAP_MAX.store(1, Ordering::Relaxed);
        let (a, mut b) = tokio::io::duplex(1 << 16);
        let mut f = FragmentStream::new(a);
        let body = vec![7u8; 700];
        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(body.len() as u16).to_be_bytes());
        rec.extend_from_slice(&body);
        f.write_all(&rec).await.unwrap();
        f.write_all(b"after").await.unwrap();
        drop(f);
        let mut got = Vec::new();
        b.read_to_end(&mut got).await.unwrap();
        // записи пересобираются в исходное сообщение
        let mut p = 0;
        let mut joined = Vec::new();
        let mut records = 0;
        while got[p] == 0x16 {
            let l = u16::from_be_bytes([got[p + 3], got[p + 4]]) as usize;
            assert!(l <= 200, "запись длиннее заданного предела");
            joined.extend_from_slice(&got[p + 5..p + 5 + l]);
            p += 5 + l;
            records += 1;
        }
        assert!(records >= 4, "рукопожатие должно уйти несколькими записями, а ушло {records}");
        assert_eq!(joined, body);
        assert_eq!(&got[p..], b"after");
    }
}
