//! Hysteria2: QUIC + аутентификация через HTTP/3, TCP — двунаправленные потоки,
//! UDP — QUIC-датаграммы с фрагментацией. Опционально обфускация Salamander.

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, OnceLock};

use bytes::Bytes;
use parking_lot::Mutex;
use rand::Rng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

use super::quic::{self, get_varint, put_varint, read_varint, QuicOpts};
use crate::common::{io_err, Address, BoxStream, Host};
use crate::config::Profile;

struct Client {
    _endpoint: quinn::Endpoint,
    conn: quinn::Connection,
    _h3: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    udp: bool,
    sessions: Mutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>,
    next_sid: AtomicU32,
}

fn clients() -> &'static tokio::sync::Mutex<HashMap<String, Arc<Client>>> {
    static C: OnceLock<tokio::sync::Mutex<HashMap<String, Arc<Client>>>> = OnceLock::new();
    C.get_or_init(|| tokio::sync::Mutex::new(HashMap::new()))
}

fn padding(min: usize, max: usize) -> String {
    let n = rand::thread_rng().gen_range(min..max);
    let chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    (0..n).map(|_| chars[rand::thread_rng().gen_range(0..chars.len())] as char).collect()
}

fn addr_string(a: &Address) -> String {
    match &a.host {
        Host::Domain(d) => format!("{d}:{}", a.port),
        _ => a.to_string(),
    }
}

async fn get_client(p: &Profile) -> io::Result<Arc<Client>> {
    let key = crate::links::to_link(p);
    let mut map = clients().lock().await;
    if let Some(c) = map.get(&key) {
        if c.conn.close_reason().is_none() {
            return Ok(c.clone());
        }
    }
    let opts = QuicOpts {
        server: crate::transport::server_addr(p),
        sni: if p.sni.is_empty() { p.address.clone() } else { p.sni.clone() },
        alpn: vec!["h3".into()],
        cert: crate::transport::certs::CertPolicy::of(p),
        salamander: if p.obfs == "salamander" { Some(p.obfs_password.as_bytes().to_vec()) } else { None },
        hop_ports: quic::parse_ports(&p.ports),
        congestion: p.congestion.clone(),
    };
    let (endpoint, conn) = quic::connect(&opts).await?;

    // аутентификация HTTP/3: POST https://hysteria/auth → 233
    let (mut driver, mut send) = h3::client::new(h3_quinn::Connection::new(conn.clone()))
        .await
        .map_err(|e| io_err(format!("Hysteria2 HTTP/3: {e}")))?;
    tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });
    let req = http::Request::post("https://hysteria/auth")
        .header("Hysteria-Auth", p.id_or_password.as_str())
        .header("Hysteria-CC-RX", "0")
        .header("Hysteria-Padding", padding(64, 512))
        .body(())
        .map_err(|e| io_err(e.to_string()))?;
    let resp = async {
        let mut st = send.send_request(req).await?;
        st.finish().await?;
        st.recv_response().await
    }
    .await
    .map_err(|e| io_err(format!("Hysteria2 auth: {e}")))?;
    if resp.status().as_u16() != 233 {
        return Err(io_err(format!("Hysteria2: аутентификация отклонена — неверный пароль (HTTP {})", resp.status())));
    }
    let udp = resp.headers().get("Hysteria-UDP").map(|v| v.as_bytes() == b"true").unwrap_or(false);
    let client = Arc::new(Client {
        _endpoint: endpoint,
        conn,
        _h3: send,
        udp,
        sessions: Mutex::new(HashMap::new()),
        next_sid: AtomicU32::new(1),
    });
    // приём UDP-датаграмм
    let c2 = client.clone();
    tokio::spawn(async move {
        let mut frags: HashMap<(u32, u16), Vec<Option<Vec<u8>>>> = HashMap::new();
        while let Ok(d) = c2.conn.read_datagram().await {
            if d.len() < 8 {
                continue;
            }
            let sid = u32::from_be_bytes([d[0], d[1], d[2], d[3]]);
            let pid = u16::from_be_bytes([d[4], d[5]]);
            let (fid, fcnt) = (d[6] as usize, d[7] as usize);
            let Some((alen, vl)) = get_varint(&d[8..]) else { continue };
            let start = 8 + vl + alen as usize;
            if start > d.len() || fcnt == 0 || fid >= fcnt {
                continue;
            }
            let payload = d[start..].to_vec();
            let full = if fcnt == 1 {
                Some(payload)
            } else {
                let e = frags.entry((sid, pid)).or_insert_with(|| vec![None; fcnt]);
                if e.len() != fcnt {
                    *e = vec![None; fcnt];
                }
                e[fid] = Some(payload);
                if e.iter().all(|x| x.is_some()) {
                    let parts = frags.remove(&(sid, pid)).unwrap();
                    Some(parts.into_iter().flatten().flatten().collect())
                } else {
                    if frags.len() > 256 {
                        frags.clear();
                    }
                    None
                }
            };
            if let Some(pkt) = full {
                let tx = c2.sessions.lock().get(&sid).cloned();
                if let Some(tx) = tx {
                    let _ = tx.try_send(pkt);
                }
            }
        }
    });
    map.insert(key, client.clone());
    Ok(client)
}

pub fn reset() {
    if let Ok(mut m) = clients().try_lock() {
        for (_, c) in m.drain() {
            c.conn.close(0u32.into(), b"");
        }
    }
}

/// Убрать клиента из кэша: соединение не отвечает (например, сменилась сеть).
async fn discard(p: &Profile, c: &Arc<Client>) {
    c.conn.close(0u32.into(), b"");
    let key = crate::links::to_link(p);
    let mut map = clients().lock().await;
    if map.get(&key).map(|x| Arc::ptr_eq(x, c)).unwrap_or(false) {
        map.remove(&key);
    }
}

async fn open_tcp(c: &Client, dest: &Address) -> io::Result<(quinn::SendStream, quinn::RecvStream)> {
    let (mut send, mut recv) = c.conn.open_bi().await.map_err(|e| io_err(format!("Hysteria2: {e}")))?;
    let addr = addr_string(dest);
    let pad = padding(64, 512);
    let mut req = Vec::with_capacity(addr.len() + pad.len() + 16);
    put_varint(0x401, &mut req);
    put_varint(addr.len() as u64, &mut req);
    req.extend_from_slice(addr.as_bytes());
    put_varint(pad.len() as u64, &mut req);
    req.extend_from_slice(pad.as_bytes());
    send.write_all(&req).await.map_err(|e| io_err(e.to_string()))?;
    let status = recv.read_u8().await?;
    let ml = read_varint(&mut recv).await? as usize;
    let mut msg = vec![0u8; ml.min(4096)];
    AsyncReadExt::read_exact(&mut recv, &mut msg).await?;
    let pl = read_varint(&mut recv).await? as usize;
    let mut pd = vec![0u8; pl.min(4096)];
    AsyncReadExt::read_exact(&mut recv, &mut pd).await?;
    if status != 0 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("Hysteria2: сервер отказал: {}", String::from_utf8_lossy(&msg)),
        ));
    }
    Ok((send, recv))
}

pub async fn tcp(p: &Profile, app: BoxStream, dest: &Address) -> io::Result<()> {
    let mut last = io_err("Hysteria2: нет соединения");
    // запрос не дошёл или сервер молчит — соединение мертво: пробуем ещё раз на новом
    for _ in 0..2 {
        let c = get_client(p).await?;
        match tokio::time::timeout(std::time::Duration::from_secs(8), open_tcp(&c, dest)).await {
            Ok(Ok((send, recv))) => return crate::common::relay(app, tokio::io::join(recv, send)).await,
            Ok(Err(e)) if e.kind() == io::ErrorKind::ConnectionRefused => return Err(e),
            Ok(Err(e)) => last = e,
            Err(_) => last = io_err("Hysteria2: сервер не отвечает"),
        }
        discard(p, &c).await;
    }
    Err(last)
}

pub async fn udp(p: &Profile, mut app: BoxStream, dest: &Address) -> io::Result<()> {
    let c = get_client(p).await?;
    if !c.udp {
        return Err(io_err("Hysteria2: UDP отключён на сервере"));
    }
    let sid = c.next_sid.fetch_add(1, Ordering::Relaxed);
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(256);
    c.sessions.lock().insert(sid, tx);
    let addr = addr_string(dest);
    let mut pid: u16 = 0;
    let mut buf = vec![0u8; 65536];
    let r: io::Result<()> = async {
        loop {
            tokio::select! {
                r = app.read(&mut buf) => {
                    let n = r?;
                    if n == 0 { break; }
                    let max = c.conn.max_datagram_size().unwrap_or(1200);
                    let mut head = Vec::with_capacity(16 + addr.len());
                    head.extend_from_slice(&sid.to_be_bytes());
                    head.extend_from_slice(&pid.to_be_bytes());
                    head.extend_from_slice(&[0, 1]);
                    put_varint(addr.len() as u64, &mut head);
                    head.extend_from_slice(addr.as_bytes());
                    let room = max.saturating_sub(head.len()).max(1);
                    let parts: Vec<&[u8]> = buf[..n].chunks(room).collect();
                    if parts.len() > 255 { continue; }
                    for (i, part) in parts.iter().enumerate() {
                        let mut d = head.clone();
                        d[6] = i as u8;
                        d[7] = parts.len() as u8;
                        d.extend_from_slice(part);
                        let _ = c.conn.send_datagram(Bytes::from(d));
                    }
                    pid = pid.wrapping_add(1);
                }
                pkt = rx.recv() => {
                    match pkt {
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
    c.sessions.lock().remove(&sid);
    r
}
