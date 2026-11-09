//! Trojan.

use std::io;

use sha2::{Digest, Sha224};
use tokio::io::AsyncWriteExt;

use crate::common::{Address, BoxStream};
use crate::config::Profile;
use crate::transport;

fn header(p: &Profile, cmd: u8, dest: &Address) -> Vec<u8> {
    let hash = Sha224::digest(p.id_or_password.as_bytes());
    let mut h = Vec::with_capacity(128);
    for b in hash {
        h.extend_from_slice(format!("{b:02x}").as_bytes());
    }
    h.extend_from_slice(b"\r\n");
    h.push(cmd);
    dest.write_socks(&mut h);
    h.extend_from_slice(b"\r\n");
    h
}

pub async fn tcp(p: &Profile, mut app: BoxStream, dest: &Address) -> io::Result<()> {
    let mut server = transport::dial(p).await?;
    let mut h = header(p, 1, dest);
    h.extend_from_slice(&super::vless::first_payload(&mut app, 50).await?);
    server.write_all(&h).await?;
    crate::common::relay(app, server).await
}

pub async fn udp(p: &Profile, app: BoxStream, dest: &Address) -> io::Result<()> {
    let mut server = transport::dial(p).await?;
    server.write_all(&header(p, 3, dest)).await?;
    super::udp_over_stream(app, server, super::UdpFraming::Trojan(dest.clone())).await
}
