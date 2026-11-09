//! Общие типы: адреса назначения, потоки, утилиты ввода-вывода.

use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

/// Любой двунаправленный асинхронный поток.
pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> AsyncStream for T {}
pub type BoxStream = Box<dyn AsyncStream>;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Host {
    Ip(IpAddr),
    Domain(String),
}

/// Адрес назначения соединения.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Address {
    pub host: Host,
    pub port: u16,
}

impl Address {
    pub fn new_domain(d: impl Into<String>, port: u16) -> Self {
        let d: String = d.into();
        if let Ok(ip) = d.trim_start_matches('[').trim_end_matches(']').parse::<IpAddr>() {
            return Address { host: Host::Ip(ip), port };
        }
        Address { host: Host::Domain(d), port }
    }
    pub fn from_socket(sa: SocketAddr) -> Self {
        Address { host: Host::Ip(sa.ip()), port: sa.port() }
    }
    pub fn domain(&self) -> Option<&str> {
        match &self.host {
            Host::Domain(d) => Some(d),
            _ => None,
        }
    }
    pub fn ip(&self) -> Option<IpAddr> {
        match &self.host {
            Host::Ip(ip) => Some(*ip),
            _ => None,
        }
    }

    /// Формат SOCKS5 / Trojan / Shadowsocks: ATYP(1=v4,3=domain,4=v6) + addr + port.
    pub fn write_socks(&self, out: &mut Vec<u8>) {
        match &self.host {
            Host::Ip(IpAddr::V4(v4)) => {
                out.push(1);
                out.extend_from_slice(&v4.octets());
            }
            Host::Ip(IpAddr::V6(v6)) => {
                out.push(4);
                out.extend_from_slice(&v6.octets());
            }
            Host::Domain(d) => {
                out.push(3);
                out.push(d.len().min(255) as u8);
                out.extend_from_slice(&d.as_bytes()[..d.len().min(255)]);
            }
        }
        out.extend_from_slice(&self.port.to_be_bytes());
    }

    /// Формат VLESS / VMess: port + ATYP(1=v4,2=domain,3=v6) + addr.
    pub fn write_vless(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.port.to_be_bytes());
        match &self.host {
            Host::Ip(IpAddr::V4(v4)) => {
                out.push(1);
                out.extend_from_slice(&v4.octets());
            }
            Host::Domain(d) => {
                out.push(2);
                out.push(d.len().min(255) as u8);
                out.extend_from_slice(&d.as_bytes()[..d.len().min(255)]);
            }
            Host::Ip(IpAddr::V6(v6)) => {
                out.push(3);
                out.extend_from_slice(&v6.octets());
            }
        }
    }

    /// Разбор адреса в формате SOCKS5 из буфера. Возвращает адрес и число прочитанных байт.
    pub fn parse_socks(buf: &[u8]) -> Option<(Address, usize)> {
        let atyp = *buf.first()?;
        let (host, off) = match atyp {
            1 => {
                let b: [u8; 4] = buf.get(1..5)?.try_into().ok()?;
                (Host::Ip(IpAddr::V4(Ipv4Addr::from(b))), 5)
            }
            4 => {
                let b: [u8; 16] = buf.get(1..17)?.try_into().ok()?;
                (Host::Ip(IpAddr::V6(Ipv6Addr::from(b))), 17)
            }
            3 => {
                let l = *buf.get(1)? as usize;
                let d = buf.get(2..2 + l)?;
                (Host::Domain(String::from_utf8_lossy(d).into_owned()), 2 + l)
            }
            _ => return None,
        };
        let p = buf.get(off..off + 2)?;
        Some((Address { host, port: u16::from_be_bytes([p[0], p[1]]) }, off + 2))
    }

    pub async fn read_socks<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Address> {
        let atyp = r.read_u8().await?;
        let host = match atyp {
            1 => {
                let mut b = [0u8; 4];
                r.read_exact(&mut b).await?;
                Host::Ip(IpAddr::V4(Ipv4Addr::from(b)))
            }
            4 => {
                let mut b = [0u8; 16];
                r.read_exact(&mut b).await?;
                Host::Ip(IpAddr::V6(Ipv6Addr::from(b)))
            }
            3 => {
                let l = r.read_u8().await? as usize;
                let mut b = vec![0u8; l];
                r.read_exact(&mut b).await?;
                Host::Domain(String::from_utf8_lossy(&b).into_owned())
            }
            _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "bad address type")),
        };
        let port = r.read_u16().await?;
        Ok(Address { host, port })
    }

    /// Разрешение адреса в SocketAddr (системный резолвер).
    pub async fn resolve(&self) -> io::Result<SocketAddr> {
        match &self.host {
            Host::Ip(ip) => Ok(SocketAddr::new(*ip, self.port)),
            Host::Domain(d) => {
                let mut it = tokio::net::lookup_host((d.as_str(), self.port)).await?;
                let all: Vec<SocketAddr> = it.by_ref().collect();
                all.iter()
                    .find(|a| a.is_ipv4())
                    .or_else(|| all.first())
                    .copied()
                    .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("cannot resolve {d}")))
            }
        }
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.host {
            Host::Ip(IpAddr::V6(v6)) => write!(f, "[{}]:{}", v6, self.port),
            Host::Ip(ip) => write!(f, "{}:{}", ip, self.port),
            Host::Domain(d) => write!(f, "{}:{}", d, self.port),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    Tcp,
    Udp,
}

/// Глобальные счётчики трафика (через прокси).
#[derive(Default)]
pub struct Stats {
    pub up: AtomicU64,
    pub down: AtomicU64,
}

/// Поток, прибавляющий прочитанные/записанные байты к счётчикам.
/// Чтение из приложения = отправка (up), запись в приложение = приём (down).
pub struct CountingStream<S> {
    inner: S,
    stats: Arc<Stats>,
}

impl<S> CountingStream<S> {
    pub fn new(inner: S, stats: Arc<Stats>) -> Self {
        Self { inner, stats }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for CountingStream<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let r = Pin::new(&mut self.inner).poll_read(cx, buf);
        let n = buf.filled().len() - before;
        if n > 0 {
            self.stats.up.fetch_add(n as u64, Ordering::Relaxed);
        }
        r
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CountingStream<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let r = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &r {
            self.stats.down.fetch_add(*n as u64, Ordering::Relaxed);
        }
        r
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Поток с заранее прочитанными байтами (после сниффинга).
pub struct PrefixedStream<S> {
    prefix: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S> PrefixedStream<S> {
    pub fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self { prefix, pos: 0, inner }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if self.pos < self.prefix.len() {
            let n = (self.prefix.len() - self.pos).min(buf.remaining());
            let start = self.pos;
            buf.put_slice(&self.prefix[start..start + n]);
            self.pos += n;
            if self.pos >= self.prefix.len() {
                self.prefix = Vec::new();
                self.pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub const IDLE_TIMEOUT_SECS: u64 = 300;
pub const HALF_CLOSE_TIMEOUT_SECS: u64 = 2;

/// Двунаправленная пересылка с таймаутом простоя (как policy в Xray:
/// connIdle = 300 с, после закрытия одной стороны — 2 с).
pub async fn relay<A, B>(a: A, b: B) -> io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    use std::sync::atomic::AtomicU8;
    use tokio::time::{Duration, Instant};

    let (mut ar, mut aw) = tokio::io::split(a);
    let (mut br, mut bw) = tokio::io::split(b);
    let start = Instant::now();
    let last = AtomicU64::new(0);
    let done = AtomicU8::new(0);

    let touch = || last.store(start.elapsed().as_millis() as u64, Ordering::Relaxed);

    let up = async {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = match ar.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            touch();
            if bw.write_all(&buf[..n]).await.is_err() {
                break;
            }
        }
        let _ = bw.shutdown().await;
        done.fetch_add(1, Ordering::Relaxed);
    };
    let down = async {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = match br.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            touch();
            if aw.write_all(&buf[..n]).await.is_err() {
                break;
            }
        }
        let _ = aw.shutdown().await;
        done.fetch_add(1, Ordering::Relaxed);
    };
    let watchdog = async {
        loop {
            tokio::time::sleep(Duration::from_millis(500)).await;
            let idle = start.elapsed().as_millis() as u64 - last.load(Ordering::Relaxed);
            let limit = if done.load(Ordering::Relaxed) > 0 {
                HALF_CLOSE_TIMEOUT_SECS * 1000
            } else {
                IDLE_TIMEOUT_SECS * 1000
            };
            if idle > limit {
                break;
            }
        }
    };
    let both = async {
        tokio::join!(up, down);
    };
    tokio::select! {
        _ = both => {},
        _ = watchdog => {},
    }
    Ok(())
}

/// Чтение одной датаграммы из "пакетного" потока (UDP-поток ipstack).
pub async fn read_packet<R: AsyncRead + Unpin>(r: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    r.read(buf).await
}

pub fn io_err(msg: impl Into<String>) -> io::Error {
    io::Error::other(msg.into())
}

/// Заполнение случайными байтами.
pub fn random_bytes(buf: &mut [u8]) {
    use rand::RngCore;
    rand::thread_rng().fill_bytes(buf);
}

pub fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_broadcast() || v4.is_unspecified() || v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64
        }
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.is_unspecified() || (v6.segments()[0] & 0xfe00) == 0xfc00 || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// Ожидание двух половин пересылки: если первой закончилась отправка —
/// ждём ответ до IDLE_TIMEOUT, если приём — даём отправке HALF_CLOSE_TIMEOUT.
pub async fn join_halves<U, D>(up: U, down: D) -> io::Result<()>
where
    U: std::future::Future<Output = io::Result<()>>,
    D: std::future::Future<Output = io::Result<()>>,
{
    use tokio::time::{timeout, Duration};
    tokio::pin!(up);
    tokio::pin!(down);
    tokio::select! {
        r = &mut up => {
            r?;
            match timeout(Duration::from_secs(IDLE_TIMEOUT_SECS), &mut down).await {
                Ok(r) => r,
                Err(_) => Ok(()),
            }
        }
        r = &mut down => {
            let _ = timeout(Duration::from_secs(HALF_CLOSE_TIMEOUT_SECS), &mut up).await;
            r
        }
    }
}
