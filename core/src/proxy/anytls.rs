//! AnyTLS (sing-box): TLS + аутентификация SHA-256(пароля) + кадры сессии.
//! Один поток на одно TLS-соединение.

use std::io;

use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::common::{io_err, Address, BoxStream};
use crate::config::Profile;
use crate::transport;

const CMD_WASTE: u8 = 0;
const CMD_SYN: u8 = 1;
const CMD_PSH: u8 = 2;
const CMD_FIN: u8 = 3;
const CMD_SETTINGS: u8 = 4;
const CMD_ALERT: u8 = 5;
const CMD_SYNACK: u8 = 7;
const CMD_HEART_REQ: u8 = 8;
const CMD_HEART_RESP: u8 = 9;

const DEFAULT_SCHEME: &str = "stop=8\n0=30-30\n1=100-400\n2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n3=9-9,500-1000\n4=500-1000\n5=500-1000\n6=500-1000\n7=500-1000";

fn frame(cmd: u8, sid: u32, data: &[u8], out: &mut Vec<u8>) {
    out.push(cmd);
    out.extend_from_slice(&sid.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
}

pub async fn tcp(p: &Profile, app: BoxStream, dest: &Address) -> io::Result<()> {
    let tcp = transport::connect_tcp(&transport::server_addr(p)).await?;
    let sni = if p.sni.is_empty() { p.address.clone() } else { p.sni.clone() };
    let tls = transport::tls_connect(tcp, &sni, &p.alpn, &transport::certs::CertPolicy::of(p)).await?;
    let (mut sr, mut sw) = tokio::io::split(tls);

    let mut first = Vec::with_capacity(256);
    first.extend_from_slice(&Sha256::digest(p.id_or_password.as_bytes()));
    first.extend_from_slice(&30u16.to_be_bytes());
    first.extend_from_slice(&[0u8; 30]);
    let md5 = format!("{:x}", md5::Md5::digest(DEFAULT_SCHEME.as_bytes()));
    frame(CMD_SETTINGS, 0, format!("v=2\nclient=xraydroid/0.1\npadding-md5={md5}").as_bytes(), &mut first);
    frame(CMD_SYN, 1, &[], &mut first);
    let mut addr = Vec::new();
    dest.write_socks(&mut addr);
    frame(CMD_PSH, 1, &addr, &mut first);
    sw.write_all(&first).await?;

    let (mut ar, mut aw) = tokio::io::split(app);
    let up = async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = ar.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            let mut f = Vec::with_capacity(n + 7);
            frame(CMD_PSH, 1, &buf[..n], &mut f);
            sw.write_all(&f).await?;
        }
        let mut f = Vec::new();
        frame(CMD_FIN, 1, &[], &mut f);
        let _ = sw.write_all(&f).await;
        Ok::<_, io::Error>(())
    };
    let down = async move {
        let r: io::Result<()> = async {
            loop {
                let mut h = [0u8; 7];
                if sr.read_exact(&mut h).await.is_err() {
                    break;
                }
                let cmd = h[0];
                let sid = u32::from_be_bytes([h[1], h[2], h[3], h[4]]);
                let len = u16::from_be_bytes([h[5], h[6]]) as usize;
                let mut data = vec![0u8; len];
                sr.read_exact(&mut data).await?;
                match cmd {
                    CMD_PSH if sid == 1 => aw.write_all(&data).await?,
                    CMD_FIN if sid == 1 => break,
                    CMD_SYNACK if !data.is_empty() => {
                        return Err(io_err(format!("AnyTLS: {}", String::from_utf8_lossy(&data))));
                    }
                    CMD_ALERT => return Err(io_err(format!("AnyTLS: {}", String::from_utf8_lossy(&data)))),
                    CMD_HEART_REQ | CMD_HEART_RESP | CMD_WASTE => {}
                    _ => {}
                }
            }
            Ok(())
        }
        .await;
        let _ = aw.shutdown().await;
        r
    };
    crate::common::join_halves(up, down).await
}
