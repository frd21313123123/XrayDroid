//! REALITY: см. `tls13` (режим `Mode::Reality`).

use std::io;

pub use super::tls13::RealityConfig;
use super::secure::SecureConn;
use crate::common::BoxStream;

pub type RealityConn = SecureConn;

pub async fn connect(tcp: tokio::net::TcpStream, cfg: &RealityConfig) -> io::Result<SecureConn> {
    tcp.set_nodelay(true).ok();
    connect_stream(Box::new(tcp), cfg).await
}

pub async fn connect_stream(io: BoxStream, cfg: &RealityConfig) -> io::Result<SecureConn> {
    super::tls13::handshake(io, &cfg.server_name, &cfg.alpn, super::tls13::Mode::Reality(cfg)).await
}
