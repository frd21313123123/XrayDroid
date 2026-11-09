//! TUIC v5: QUIC, аутентификация токеном из TLS Keying Material, TCP — потоки,
//! UDP — датаграммы (режим native).

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, OnceLock};

use bytes::Bytes;
use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

use super::quic::{self, QuicOpts};
use crate::common::{io_err, Address, BoxStream, Host};
use crate::config::Profile;

const VER: u8 = 5;

struct Client {
    _endpoint: quinn::Endpoint,
    conn: quinn::Connection,
    assocs: Mutex<HashMap<u16, mpsc::Sender<Vec<u8>>>>,
    next_assoc: AtomicU16,
}

fn clients() -> &'static tokio::sync::Mutex<HashMap<String, Arc<Client>>> {
    static C: OnceLock<tokio::sync::Mutex<HashMap<String, Arc<Client>>>> = OnceLock::new();
    C.get_or_init(|| tokio::sync::Mutex::new(HashMap::new()))
}

fn write_addr(a: &Address, out: &mut Vec<u8>) {
    match &a.host {
        Host::Domain(d) => {
            out.push(0x00);
            out.push(d.len().min(255) as u8);
            out.extend_from_slice(&d.as_bytes()[..d.len().min(255)]);
        }
        Host::Ip(std::net::IpAddr::V4(v4)) => {
            out.push(0x01);
            out.extend_from_slice(&v4.octets());
        }
        Host::Ip(std::net::IpAddr::V6(v6)) => {
            out.push(0x02);
            out.extend_from_slice(&v6.octets());
        }
    }
    out.extend_from_slice(&a.port.to_be_bytes());
}

fn addr_len(b: &[u8]) -> Option<usize> {
    Some(match *b.first()? {
        0xff => 1,
        0x00 => 2 + *b.get(1)? as usize + 2,
        0x01 => 1 + 4 + 2,
        0x02 => 1 + 16 + 2,
        _ => return None,
    })
}

async fn get_client(p: &Profile) -> io::Result<Arc<Client>> {
    let key = crate::links::to_link(p);
    let mut map = clients().lock().await;
    if let Some(c) = map.get(&key) {
        if c.conn.close_reason().is_none() {
            return Ok(c.clone());
        }
    }
    let alpn: Vec<String> = p.alpn.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    let opts = QuicOpts {
        server: crate::transport::server_addr(p),
        sni: if p.sni.is_empty() { p.address.clone() } else { p.sni.clone() },
        alpn: if alpn.is_empty() { vec!["h3".into()] } else { alpn },
        cert: crate::transport::certs::CertPolicy::of(p),
        salamander: None,
    };
    let (endpoint, conn) = quic::connect(&opts).await?;
    let uuid = super::vless::parse_uuid(&p.id_or_password)?;
    let mut token = [0u8; 32];
    conn.export_keying_material(&mut token, &uuid, p.secret.as_bytes())
        .map_err(|_| io_err("TUIC: не удалось получить keying material"))?;
    let mut auth = vec![VER, 0x00];
    auth.extend_from_slice(&uuid);
    auth.extend_from_slice(&token);
    let mut uni = conn.open_uni().await.map_err(|e| io_err(format!("TUIC: {e}")))?;
    uni.write_all(&auth).await.map_err(|e| io_err(e.to_string()))?;
    let _ = uni.finish();

    let client = Arc::new(Client { _endpoint: endpoint, conn, assocs: Mutex::new(HashMap::new()), next_assoc: AtomicU16::new(1) });
    let c2 = client.clone();
    tokio::spawn(async move {
        let mut frags: HashMap<(u16, u16), Vec<Option<Vec<u8>>>> = HashMap::new();
        while let Ok(d) = c2.conn.read_datagram().await {
            // [VER][0x02][ASSOC u16][PKT u16][FRAG_TOTAL][FRAG_ID][SIZE u16][ADDR][DATA]
            if d.len() < 10 || d[0] != VER || d[1] != 0x02 {
                continue;
            }
            let assoc = u16::from_be_bytes([d[2], d[3]]);
            let pkt = u16::from_be_bytes([d[4], d[5]]);
            let (total, fid) = (d[6] as usize, d[7] as usize);
            let size = u16::from_be_bytes([d[8], d[9]]) as usize;
            let Some(al) = addr_len(&d[10..]) else { continue };
            let start = 10 + al;
            if start + size > d.len() || total == 0 || fid >= total {
                continue;
            }
            let payload = d[start..start + size].to_vec();
            let full = if total == 1 {
                Some(payload)
            } else {
                let e = frags.entry((assoc, pkt)).or_insert_with(|| vec![None; total]);
                e[fid] = Some(payload);
                if e.iter().all(|x| x.is_some()) {
                    Some(frags.remove(&(assoc, pkt)).unwrap().into_iter().flatten().flatten().collect())
                } else {
                    if frags.len() > 256 {
                        frags.clear();
                    }
                    None
                }
            };
            if let Some(v) = full {
                let tx = c2.assocs.lock().get(&assoc).cloned();
                if let Some(tx) = tx {
                    let _ = tx.try_send(v);
                }
            }
        }
    });
    map.insert(key, client.clone());
    Ok(client)
}

pub async fn tcp(p: &Profile, app: BoxStream, dest: &Address) -> io::Result<()> {
    let c = get_client(p).await?;
    let (mut send, recv) = c.conn.open_bi().await.map_err(|e| io_err(format!("TUIC: {e}")))?;
    let mut h = vec![VER, 0x01];
    write_addr(dest, &mut h);
    send.write_all(&h).await.map_err(|e| io_err(e.to_string()))?;
    crate::common::relay(app, tokio::io::join(recv, send)).await
}

pub async fn udp(p: &Profile, mut app: BoxStream, dest: &Address) -> io::Result<()> {
    let c = get_client(p).await?;
    let assoc = c.next_assoc.fetch_add(1, Ordering::Relaxed);
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(256);
    c.assocs.lock().insert(assoc, tx);
    let mut pkt: u16 = 0;
    let mut buf = vec![0u8; 65536];
    let r: io::Result<()> = async {
        loop {
            tokio::select! {
                r = app.read(&mut buf) => {
                    let n = r?;
                    if n == 0 { break; }
                    let max = c.conn.max_datagram_size().unwrap_or(1200);
                    let mut addr = Vec::new();
                    write_addr(dest, &mut addr);
                    let room = max.saturating_sub(10 + addr.len()).max(1);
                    let parts: Vec<&[u8]> = buf[..n].chunks(room).collect();
                    if parts.len() > 255 { continue; }
                    for (i, part) in parts.iter().enumerate() {
                        let mut d = vec![VER, 0x02];
                        d.extend_from_slice(&assoc.to_be_bytes());
                        d.extend_from_slice(&pkt.to_be_bytes());
                        d.push(parts.len() as u8);
                        d.push(i as u8);
                        d.extend_from_slice(&(part.len() as u16).to_be_bytes());
                        // адрес указывается только в первом фрагменте
                        if i == 0 { d.extend_from_slice(&addr); } else { d.push(0xff); }
                        d.extend_from_slice(part);
                        let _ = c.conn.send_datagram(Bytes::from(d));
                    }
                    pkt = pkt.wrapping_add(1);
                }
                v = rx.recv() => {
                    match v {
                        Some(v) => app.write_all(&v).await?,
                        None => break,
                    }
                }
                _ = tokio::time::sleep(super::UDP_IDLE) => break,
            }
        }
        Ok(())
    }
    .await;
    c.assocs.lock().remove(&assoc);
    // Dissociate
    if let Ok(mut uni) = c.conn.open_uni().await {
        let mut d = vec![VER, 0x03];
        d.extend_from_slice(&assoc.to_be_bytes());
        let _ = uni.write_all(&d).await;
        let _ = uni.finish();
    }
    r
}
