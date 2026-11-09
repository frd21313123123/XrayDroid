//! Исходящие соединения (outbounds).

pub mod shadowsocks;
pub mod socks;
pub mod trojan;
pub mod vision;
pub mod vless;
pub mod vmess;

use std::io;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::common::{io_err, Address, BoxStream};
use crate::config::{Profile, Protocol};

#[derive(Clone)]
pub enum Outbound {
    Direct,
    Block,
    Proxy(Arc<Profile>),
}

impl Outbound {
    pub fn name(&self) -> &'static str {
        match self {
            Outbound::Direct => "direct",
            Outbound::Block => "block",
            Outbound::Proxy(_) => "proxy",
        }
    }

    pub async fn handle_tcp(&self, app: BoxStream, dest: &Address) -> io::Result<()> {
        match self {
            Outbound::Block => Ok(()),
            Outbound::Direct => {
                let s = crate::transport::connect_tcp(dest).await?;
                crate::common::relay(app, s).await
            }
            Outbound::Proxy(p) => match p.protocol {
                Protocol::Vless => vless::tcp(p, app, dest).await,
                Protocol::Vmess => vmess::tcp(p, app, dest).await,
                Protocol::Trojan => trojan::tcp(p, app, dest).await,
                Protocol::Shadowsocks => shadowsocks::tcp(p, app, dest).await,
                Protocol::Socks => socks::tcp(p, app, dest).await,
            },
        }
    }

    /// `app` — "пакетный" поток: одно чтение/запись = одна датаграмма.
    pub async fn handle_udp(&self, app: BoxStream, dest: &Address) -> io::Result<()> {
        match self {
            Outbound::Block => Ok(()),
            Outbound::Direct => udp_direct(app, dest).await,
            Outbound::Proxy(p) => match p.protocol {
                Protocol::Vless => vless::udp(p, app, dest).await,
                Protocol::Vmess => vmess::udp(p, app, dest).await,
                Protocol::Trojan => trojan::udp(p, app, dest).await,
                Protocol::Shadowsocks => shadowsocks::udp(p, app, dest).await,
                Protocol::Socks => Err(io_err("UDP через SOCKS не поддерживается")),
            },
        }
    }
}

pub const UDP_IDLE: Duration = Duration::from_secs(60);

async fn udp_direct(mut app: BoxStream, dest: &Address) -> io::Result<()> {
    let target = dest.resolve().await?;
    let bind: std::net::SocketAddr = if target.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }.parse().unwrap();
    let sock = tokio::net::UdpSocket::bind(bind).await?;
    sock.connect(target).await?;
    let mut a = vec![0u8; 65536];
    let mut b = vec![0u8; 65536];
    loop {
        tokio::select! {
            r = app.read(&mut a) => {
                let n = r?;
                if n == 0 { break; }
                sock.send(&a[..n]).await?;
            }
            r = sock.recv(&mut b) => {
                let n = r?;
                app.write_all(&b[..n]).await?;
            }
            _ = tokio::time::sleep(UDP_IDLE) => break,
        }
    }
    Ok(())
}

pub enum UdpFraming {
    /// VLESS: len(2) + payload
    LenPrefixed,
    /// Trojan: addr + len(2) + CRLF + payload
    Trojan(Address),
}

/// Пересылка датаграмм через потоковое соединение с заданным кадрированием.
pub async fn udp_over_stream<S>(app: BoxStream, server: S, framing: UdpFraming) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let (mut ar, mut aw) = tokio::io::split(app);
    let (mut sr, mut sw) = tokio::io::split(server);
    let framing = Arc::new(framing);
    let f2 = framing.clone();
    let up = async move {
        let mut buf = vec![0u8; 65536];
        loop {
            let n = match tokio::time::timeout(UDP_IDLE, ar.read(&mut buf)).await {
                Ok(Ok(0)) | Err(_) => break,
                Ok(Ok(n)) => n,
                Ok(Err(e)) => return Err(e),
            };
            let mut out = Vec::with_capacity(n + 32);
            match &*f2 {
                UdpFraming::LenPrefixed => {
                    out.extend_from_slice(&(n as u16).to_be_bytes());
                }
                UdpFraming::Trojan(dest) => {
                    dest.write_socks(&mut out);
                    out.extend_from_slice(&(n as u16).to_be_bytes());
                    out.extend_from_slice(b"\r\n");
                }
            }
            out.extend_from_slice(&buf[..n]);
            sw.write_all(&out).await?;
        }
        let _ = sw.shutdown().await;
        Ok::<_, io::Error>(())
    };
    let down = async move {
        loop {
            let pkt = match &*framing {
                UdpFraming::LenPrefixed => {
                    let len = match tokio::time::timeout(UDP_IDLE, sr.read_u16()).await {
                        Ok(Ok(l)) => l as usize,
                        _ => break,
                    };
                    let mut v = vec![0u8; len];
                    sr.read_exact(&mut v).await?;
                    v
                }
                UdpFraming::Trojan(_) => {
                    match tokio::time::timeout(UDP_IDLE, Address::read_socks(&mut sr)).await {
                        Ok(Ok(_)) => {}
                        _ => break,
                    }
                    let len = sr.read_u16().await? as usize;
                    let mut crlf = [0u8; 2];
                    sr.read_exact(&mut crlf).await?;
                    let mut v = vec![0u8; len];
                    sr.read_exact(&mut v).await?;
                    v
                }
            };
            aw.write_all(&pkt).await?;
        }
        Ok::<_, io::Error>(())
    };
    tokio::select! {
        r = up => r,
        r = down => r,
    }
}
