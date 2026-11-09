//! Shadowsocks (AEAD и 2022) на базе библиотеки shadowsocks-rust.

use std::io;
use std::sync::OnceLock;

use shadowsocks::config::{ServerAddr, ServerConfig, ServerType};
use shadowsocks::context::{Context, SharedContext};
use shadowsocks::crypto::CipherKind;
use shadowsocks::relay::socks5::Address as SsAddress;
use shadowsocks::relay::tcprelay::proxy_stream::ProxyClientStream;
use shadowsocks::relay::udprelay::proxy_socket::ProxySocket;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::common::{io_err, Address, BoxStream, Host};
use crate::config::Profile;
use crate::transport;

fn context() -> SharedContext {
    static CTX: OnceLock<SharedContext> = OnceLock::new();
    CTX.get_or_init(|| Context::new_shared(ServerType::Local)).clone()
}

fn ss_addr(a: &Address) -> SsAddress {
    match &a.host {
        Host::Ip(ip) => SsAddress::SocketAddress(std::net::SocketAddr::new(*ip, a.port)),
        Host::Domain(d) => SsAddress::DomainNameAddress(d.clone(), a.port),
    }
}

async fn server_config(p: &Profile) -> io::Result<ServerConfig> {
    let method: CipherKind = p.method.trim().to_lowercase().parse().map_err(|_| io_err(format!("Shadowsocks: неизвестный метод {}", p.method)))?;
    let sa = transport::server_addr(p).resolve().await?;
    ServerConfig::new(ServerAddr::SocketAddr(sa), p.id_or_password.clone(), method)
        .map_err(|e| io_err(format!("Shadowsocks: {e}")))
}

pub async fn tcp(p: &Profile, app: BoxStream, dest: &Address) -> io::Result<()> {
    let cfg = server_config(p).await?;
    let tcp = transport::connect_tcp(&transport::server_addr(p)).await?;
    let s = ProxyClientStream::from_stream(context(), tcp, &cfg, ss_addr(dest));
    crate::common::relay(app, s).await
}

pub async fn udp(p: &Profile, mut app: BoxStream, dest: &Address) -> io::Result<()> {
    let cfg = server_config(p).await?;
    let sock = ProxySocket::connect(context(), &cfg).await.map_err(|e| io_err(format!("Shadowsocks UDP: {e}")))?;
    let target = ss_addr(dest);
    let mut ctrl = shadowsocks::relay::udprelay::options::UdpSocketControlData::default();
    ctrl.client_session_id = rand::random::<u64>();
    ctrl.packet_id = 1;
    let mut a = vec![0u8; 65536];
    let mut b = vec![0u8; 65536];
    loop {
        tokio::select! {
            r = app.read(&mut a) => {
                let n = r?;
                if n == 0 { break; }
                sock.send_with_ctrl(&target, &ctrl, &a[..n]).await.map_err(|e| io_err(e.to_string()))?;
                ctrl.packet_id += 1;
            }
            r = sock.recv(&mut b) => {
                let (n, _, _) = r.map_err(|e| io_err(e.to_string()))?;
                app.write_all(&b[..n]).await?;
            }
            _ = tokio::time::sleep(super::UDP_IDLE) => break,
        }
    }
    Ok(())
}
