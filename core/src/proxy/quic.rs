//! Общий QUIC-клиент (quinn) для Hysteria2 и TUIC: TLS 1.3, BBR, обфускация Salamander.

use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use blake2::digest::{Update, VariableOutput};
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::common::{io_err, Address};

pub struct QuicOpts {
    pub server: Address,
    pub sni: String,
    pub alpn: Vec<String>,
    pub cert: crate::transport::certs::CertPolicy,
    /// Пароль Salamander (Hysteria2 obfs)
    pub salamander: Option<Vec<u8>>,
    /// Порты для port hopping (пусто — один порт сервера)
    pub hop_ports: Vec<u16>,
    /// bbr | cubic | new_reno
    pub congestion: String,
}

/// "443,20000-30000" → список портов.
pub fn parse_ports(spec: &str) -> Vec<u16> {
    let mut out = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (a, b) = part.split_once('-').unwrap_or((part, part));
        if let (Ok(a), Ok(b)) = (a.trim().parse::<u16>(), b.trim().parse::<u16>()) {
            let (a, b) = if a <= b { (a, b) } else { (b, a) };
            out.extend((a..=b).filter(|p| *p != 0));
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// Как часто меняется порт (как hopInterval в Hysteria по умолчанию).
const HOP_INTERVAL: Duration = Duration::from_secs(30);

fn tls_config(alpn: &[String], policy: &crate::transport::certs::CertPolicy) -> io::Result<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| io_err(e.to_string()))?;
    let mut cfg = crate::transport::certs::client_config(builder, policy, provider);
    cfg.alpn_protocols = alpn.iter().map(|s| s.as_bytes().to_vec()).collect();
    cfg.enable_early_data = false;
    Ok(cfg)
}

pub async fn connect(o: &QuicOpts) -> io::Result<(quinn::Endpoint, quinn::Connection)> {
    let mut target = o.server.resolve().await?;
    if let Some(first) = o.hop_ports.first() {
        if !o.hop_ports.contains(&target.port()) {
            target.set_port(*first);
        }
    }
    let bind: SocketAddr = if target.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }.parse().unwrap();
    let std_sock = std::net::UdpSocket::bind(bind)?;
    let runtime: Arc<dyn quinn::Runtime> = Arc::new(quinn::TokioRuntime);
    let sock = runtime.wrap_udp_socket(std_sock)?;
    let sock: Arc<dyn AsyncUdpSocket> = if o.hop_ports.len() > 1 {
        Arc::new(HopSocket {
            inner: sock,
            canonical: target,
            ports: o.hop_ports.clone(),
            state: parking_lot::Mutex::new((target.port(), std::time::Instant::now() + HOP_INTERVAL)),
        })
    } else {
        sock
    };
    let sock: Arc<dyn AsyncUdpSocket> = match &o.salamander {
        Some(key) => Arc::new(Salamander { inner: sock, key: key.clone() }),
        None => sock,
    };
    let mut endpoint = quinn::Endpoint::new_with_abstract_socket(quinn::EndpointConfig::default(), None, sock, runtime)?;

    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(tls_config(&o.alpn, &o.cert)?))
        .map_err(|e| io_err(format!("QUIC TLS: {e}")))?;
    let mut cfg = quinn::ClientConfig::new(Arc::new(crypto));
    let mut t = quinn::TransportConfig::default();
    t.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
    t.keep_alive_interval(Some(Duration::from_secs(10)));
    match o.congestion.trim().to_ascii_lowercase().as_str() {
        "cubic" => t.congestion_controller_factory(Arc::new(quinn::congestion::CubicConfig::default())),
        "new_reno" | "newreno" | "reno" => t.congestion_controller_factory(Arc::new(quinn::congestion::NewRenoConfig::default())),
        _ => t.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default())),
    };
    t.stream_receive_window((8u32 << 20).into());
    t.receive_window((32u32 << 20).into());
    t.send_window(32 << 20);
    t.datagram_receive_buffer_size(Some(4 << 20));
    t.max_concurrent_bidi_streams(1024u32.into());
    t.max_concurrent_uni_streams(1024u32.into());
    if o.salamander.is_some() {
        // запас под 8-байтовую соль Salamander
        t.initial_mtu(1200);
        t.mtu_discovery_config(None);
    }
    cfg.transport_config(Arc::new(t));
    endpoint.set_default_client_config(cfg);

    let sni = if o.sni.is_empty() { o.server.domain().unwrap_or("localhost").to_string() } else { o.sni.clone() };
    let connecting = endpoint.connect(target, &sni).map_err(|e| io_err(format!("QUIC: {e}")))?;
    let conn = tokio::time::timeout(crate::transport::CONNECT_TIMEOUT, connecting)
        .await
        .map_err(|_| io_err("таймаут QUIC-рукопожатия"))?
        .map_err(|e| io_err(format!("QUIC: {e}")))?;
    Ok((endpoint, conn))
}

// ───────────────────────── Port hopping ─────────────────────────

/// Отправляет пакеты на периодически меняющийся порт сервера. Для QUIC адрес сервера
/// остаётся прежним: во входящих пакетах порт подменяется обратно.
struct HopSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    canonical: SocketAddr,
    ports: Vec<u16>,
    /// (текущий порт, когда менять)
    state: parking_lot::Mutex<(u16, std::time::Instant)>,
}

impl fmt::Debug for HopSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HopSocket")
    }
}

impl HopSocket {
    fn port(&self) -> u16 {
        let mut st = self.state.lock();
        let now = std::time::Instant::now();
        if now >= st.1 {
            use rand::Rng;
            st.0 = self.ports[rand::thread_rng().gen_range(0..self.ports.len())];
            st.1 = now + HOP_INTERVAL;
            log::debug!("port hopping: {}:{}", self.canonical.ip(), st.0);
        }
        st.0
    }
}

impl AsyncUdpSocket for HopSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, t: &Transmit) -> io::Result<()> {
        self.inner.try_send(&Transmit {
            destination: SocketAddr::new(self.canonical.ip(), self.port()),
            ecn: t.ecn,
            contents: t.contents,
            segment_size: t.segment_size,
            src_ip: t.src_ip,
        })
    }

    fn poll_recv(&self, cx: &mut Context, bufs: &mut [IoSliceMut<'_>], meta: &mut [RecvMeta]) -> Poll<io::Result<usize>> {
        let r = self.inner.poll_recv(cx, bufs, meta);
        if let Poll::Ready(Ok(n)) = &r {
            for m in meta.iter_mut().take(*n) {
                if m.addr.ip() == self.canonical.ip() {
                    m.addr = self.canonical;
                }
            }
        }
        r
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

// ───────────────────────── Salamander ─────────────────────────

struct Salamander {
    inner: Arc<dyn AsyncUdpSocket>,
    key: Vec<u8>,
}

impl fmt::Debug for Salamander {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Salamander")
    }
}

fn salamander_mask(key: &[u8], salt: &[u8]) -> [u8; 32] {
    let mut h = blake2::Blake2bVar::new(32).unwrap();
    h.update(key);
    h.update(salt);
    let mut out = [0u8; 32];
    h.finalize_variable(&mut out).unwrap();
    out
}

impl AsyncUdpSocket for Salamander {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, t: &Transmit) -> io::Result<()> {
        let seg = t.segment_size.unwrap_or(t.contents.len()).max(1);
        for chunk in t.contents.chunks(seg) {
            let mut out = vec![0u8; 8 + chunk.len()];
            crate::common::random_bytes(&mut out[..8]);
            let mask = salamander_mask(&self.key, &out[..8]);
            for (i, b) in chunk.iter().enumerate() {
                out[8 + i] = b ^ mask[i % 32];
            }
            self.inner.try_send(&Transmit {
                destination: t.destination,
                ecn: t.ecn,
                contents: &out,
                segment_size: None,
                src_ip: t.src_ip,
            })?;
        }
        Ok(())
    }

    fn poll_recv(&self, cx: &mut Context, bufs: &mut [IoSliceMut<'_>], meta: &mut [RecvMeta]) -> Poll<io::Result<usize>> {
        let n = match self.inner.poll_recv(cx, bufs, meta) {
            Poll::Ready(Ok(n)) => n,
            other => return other,
        };
        for i in 0..n {
            let m = &mut meta[i];
            let buf = &mut bufs[i][..m.len];
            let stride = m.stride.max(1);
            let mut w = 0;
            let mut r = 0;
            while r < buf.len() {
                let end = (r + stride).min(buf.len());
                let seg_len = end - r;
                if seg_len > 8 {
                    let salt: [u8; 8] = buf[r..r + 8].try_into().unwrap();
                    let mask = salamander_mask(&self.key, &salt);
                    for j in 0..seg_len - 8 {
                        buf[w + j] = buf[r + 8 + j] ^ mask[j % 32];
                    }
                    w += seg_len - 8;
                }
                r = end;
            }
            m.len = w;
            m.stride = stride.saturating_sub(8).max(1);
        }
        Poll::Ready(Ok(n))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

// ───────────────────────── QUIC varint ─────────────────────────

pub fn put_varint(v: u64, out: &mut Vec<u8>) {
    if v < 1 << 6 {
        out.push(v as u8);
    } else if v < 1 << 14 {
        out.extend_from_slice(&((v as u16) | 0x4000).to_be_bytes());
    } else if v < 1 << 30 {
        out.extend_from_slice(&((v as u32) | 0x8000_0000).to_be_bytes());
    } else {
        out.extend_from_slice(&(v | 0xC000_0000_0000_0000).to_be_bytes());
    }
}

pub fn get_varint(b: &[u8]) -> Option<(u64, usize)> {
    let first = *b.first()?;
    let len = 1 << (first >> 6);
    if b.len() < len {
        return None;
    }
    let mut v = (first & 0x3f) as u64;
    for x in &b[1..len] {
        v = (v << 8) | *x as u64;
    }
    Some((v, len))
}

pub async fn read_varint<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<u64> {
    let first = r.read_u8().await?;
    let len = 1usize << (first >> 6);
    let mut v = (first & 0x3f) as u64;
    for _ in 1..len {
        v = (v << 8) | r.read_u8().await? as u64;
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    #[test]
    fn ports() {
        assert_eq!(super::parse_ports("443, 1000-1002,1001"), vec![443, 1000, 1001, 1002]);
        assert_eq!(super::parse_ports("5-3"), vec![3, 4, 5]);
        assert!(super::parse_ports("x").is_empty());
    }

    #[test]
    fn varint() {
        for v in [0u64, 63, 64, 16383, 16384, 1 << 29, 1 << 40] {
            let mut b = Vec::new();
            super::put_varint(v, &mut b);
            assert_eq!(super::get_varint(&b), Some((v, b.len())));
        }
    }
}
