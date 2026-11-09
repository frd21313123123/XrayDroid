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
    pub insecure: bool,
    /// Пароль Salamander (Hysteria2 obfs)
    pub salamander: Option<Vec<u8>>,
}

fn tls_config(alpn: &[String], insecure: bool) -> io::Result<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| io_err(e.to_string()))?;
    let mut cfg = if insecure {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(crate::transport::NoVerifyPub::new(provider)))
            .with_no_client_auth()
    } else {
        let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    cfg.alpn_protocols = alpn.iter().map(|s| s.as_bytes().to_vec()).collect();
    cfg.enable_early_data = false;
    Ok(cfg)
}

pub async fn connect(o: &QuicOpts) -> io::Result<(quinn::Endpoint, quinn::Connection)> {
    let target = o.server.resolve().await?;
    let bind: SocketAddr = if target.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }.parse().unwrap();
    let std_sock = std::net::UdpSocket::bind(bind)?;
    let runtime: Arc<dyn quinn::Runtime> = Arc::new(quinn::TokioRuntime);
    let sock = runtime.wrap_udp_socket(std_sock)?;
    let sock: Arc<dyn AsyncUdpSocket> = match &o.salamander {
        Some(key) => Arc::new(Salamander { inner: sock, key: key.clone() }),
        None => sock,
    };
    let mut endpoint = quinn::Endpoint::new_with_abstract_socket(quinn::EndpointConfig::default(), None, sock, runtime)?;

    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(tls_config(&o.alpn, o.insecure)?))
        .map_err(|e| io_err(format!("QUIC TLS: {e}")))?;
    let mut cfg = quinn::ClientConfig::new(Arc::new(crypto));
    let mut t = quinn::TransportConfig::default();
    t.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
    t.keep_alive_interval(Some(Duration::from_secs(10)));
    t.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
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
    fn varint() {
        for v in [0u64, 63, 64, 16383, 16384, 1 << 29, 1 << 40] {
            let mut b = Vec::new();
            super::put_varint(v, &mut b);
            assert_eq!(super::get_varint(&b), Some((v, b.len())));
        }
    }
}
