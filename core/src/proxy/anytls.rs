//! AnyTLS (sing-box): TLS + аутентификация SHA-256(пароля) + кадры сессии.
//! Сессии переиспользуются: после закрытия потока TLS-соединение возвращается в пул,
//! и следующий поток стартует без нового рукопожатия. UDP — через UDP-over-TCP v2.

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt, WriteHalf};
use tokio::sync::mpsc;

use crate::common::{io_err, Address, BoxStream, IDLE_TIMEOUT_SECS};
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

/// Сколько сессия может простаивать в пуле (сервер закрывает простаивающие через 30 с и больше).
const SESSION_IDLE: Duration = Duration::from_secs(25);
const MAX_IDLE_SESSIONS: usize = 8;
/// Адрес, которым sing-box обозначает поток UDP-over-TCP v2.
const UOT_MAGIC: &str = "sp.v2.udp-over-tcp.arpa";

fn frame(cmd: u8, sid: u32, data: &[u8], out: &mut Vec<u8>) {
    out.push(cmd);
    out.extend_from_slice(&sid.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
}

struct Session {
    w: WriteHalf<BoxStream>,
    /// Кадры от сервера; канал закрывается вместе с соединением
    frames: mpsc::Receiver<(u8, u32, Vec<u8>)>,
    reader: tokio::task::JoinHandle<()>,
    next_sid: u32,
    idle_since: Instant,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

fn idle_pool() -> &'static Mutex<HashMap<String, Vec<Session>>> {
    static P: OnceLock<Mutex<HashMap<String, Vec<Session>>>> = OnceLock::new();
    P.get_or_init(Default::default)
}

pub fn reset() {
    idle_pool().lock().clear();
}

fn pool_key(p: &Profile) -> String {
    format!("{}|{}|{}|{}|{}|{}", p.address, p.port, p.sni, p.id_or_password, p.allow_insecure, p.pinned_cert_sha256)
}

/// Свободная живая сессия из пула.
fn take_idle(key: &str) -> Option<Session> {
    let mut pool = idle_pool().lock();
    let list = pool.get_mut(key)?;
    while let Some(mut s) = list.pop() {
        if s.idle_since.elapsed() > SESSION_IDLE {
            continue;
        }
        // пока сессия лежала в пуле, сервер мог закрыть соединение или прислать служебные кадры
        let alive = loop {
            match s.frames.try_recv() {
                Ok((CMD_ALERT, _, _)) => break false,
                Ok(_) => {}
                Err(mpsc::error::TryRecvError::Empty) => break true,
                Err(mpsc::error::TryRecvError::Disconnected) => break false,
            }
        };
        if alive {
            return Some(s);
        }
    }
    None
}

fn put_idle(key: String, mut s: Session) {
    s.idle_since = Instant::now();
    let mut pool = idle_pool().lock();
    if pool.len() > 64 {
        pool.retain(|_, l| l.iter().any(|s| s.idle_since.elapsed() < SESSION_IDLE));
    }
    let list = pool.entry(key).or_default();
    list.retain(|s| s.idle_since.elapsed() < SESSION_IDLE);
    if list.len() < MAX_IDLE_SESSIONS {
        list.push(s);
    }
}

async fn new_session(p: &Profile) -> io::Result<Session> {
    let tcp = transport::dialer::connect_for_tls(&transport::server_addr(p)).await?;
    let sni = if p.sni.is_empty() { p.address.clone() } else { p.sni.clone() };
    let tls: BoxStream = if p.fingerprint.is_empty() {
        Box::new(transport::tls_connect(tcp, &sni, &p.alpn, &transport::certs::CertPolicy::of(p)).await?)
    } else {
        transport::tls_for_profile(tcp, p, &p.alpn).await?
    };
    let (mut sr, mut sw) = tokio::io::split(tls);

    let mut first = Vec::with_capacity(256);
    first.extend_from_slice(&Sha256::digest(p.id_or_password.as_bytes()));
    first.extend_from_slice(&30u16.to_be_bytes());
    first.extend_from_slice(&[0u8; 30]);
    let md5 = format!("{:x}", md5::Md5::digest(DEFAULT_SCHEME.as_bytes()));
    frame(CMD_SETTINGS, 0, format!("v=2\nclient=xraydroid/0.3\npadding-md5={md5}").as_bytes(), &mut first);
    sw.write_all(&first).await?;

    let (tx, rx) = mpsc::channel(64);
    let reader = tokio::spawn(async move {
        loop {
            let mut h = [0u8; 7];
            if sr.read_exact(&mut h).await.is_err() {
                break;
            }
            let sid = u32::from_be_bytes([h[1], h[2], h[3], h[4]]);
            let mut data = vec![0u8; u16::from_be_bytes([h[5], h[6]]) as usize];
            if sr.read_exact(&mut data).await.is_err() {
                break;
            }
            if matches!(h[0], CMD_WASTE | CMD_HEART_RESP) {
                continue;
            }
            if tx.send((h[0], sid, data)).await.is_err() {
                break;
            }
        }
    });
    Ok(Session { w: sw, frames: rx, reader, next_sid: 1, idle_since: Instant::now() })
}

/// Чем закончился поток.
enum End {
    /// Поток закрыт чисто — сессию можно вернуть в пул
    Clean,
    /// Сессия больше не годится
    Dead,
}

/// Пересылка одного потока. `uot` — режим UDP-over-TCP: датаграммы с префиксом длины.
async fn run_stream(s: &mut Session, sid: u32, app: BoxStream, uot: bool) -> io::Result<End> {
    let Session { w, frames, .. } = s;
    let (mut ar, mut aw) = tokio::io::split(app);
    let stop = tokio::sync::Notify::new();
    let started = Instant::now();
    let last_rx = AtomicU64::new(0);
    let up_done_at = AtomicU64::new(0);
    let idle = if uot { super::UDP_IDLE } else { Duration::from_secs(IDLE_TIMEOUT_SECS) };

    let outcome: io::Result<End> = {
        // отправка: запись кадра никогда не прерывается на середине — иначе сессию не переиспользовать
        let up = async {
            let mut buf = vec![0u8; if uot { 65536 } else { 16 * 1024 }];
            loop {
                let n = tokio::select! {
                    biased;
                    _ = stop.notified() => return Ok::<bool, io::Error>(false),
                    r = tokio::time::timeout(idle, ar.read(&mut buf)) => match r {
                        Ok(Ok(n)) => n,
                        Ok(Err(e)) => return Err(e),
                        Err(_) => 0,
                    },
                };
                if n == 0 {
                    return Ok(true);
                }
                let mut f = Vec::with_capacity(n + 16);
                if uot {
                    if n > 65000 {
                        continue;
                    }
                    let mut d = Vec::with_capacity(n + 2);
                    d.extend_from_slice(&(n as u16).to_be_bytes());
                    d.extend_from_slice(&buf[..n]);
                    frame(CMD_PSH, sid, &d, &mut f);
                } else {
                    frame(CMD_PSH, sid, &buf[..n], &mut f);
                }
                w.write_all(&f).await?;
            }
        };
        let down = async {
            let mut pending: Vec<u8> = Vec::new();
            loop {
                let Some((cmd, fsid, data)) = frames.recv().await else {
                    return Err(io_err("AnyTLS: сервер закрыл соединение"));
                };
                match cmd {
                    CMD_PSH if fsid == sid => {
                        last_rx.store(started.elapsed().as_millis() as u64, Ordering::Relaxed);
                        if !uot {
                            aw.write_all(&data).await?;
                            continue;
                        }
                        pending.extend_from_slice(&data);
                        while pending.len() >= 2 {
                            let l = u16::from_be_bytes([pending[0], pending[1]]) as usize;
                            if pending.len() < 2 + l {
                                break;
                            }
                            aw.write_all(&pending[2..2 + l]).await?;
                            pending.drain(..2 + l);
                        }
                    }
                    CMD_FIN if fsid == sid => return Ok(()),
                    CMD_SYNACK if fsid == sid && !data.is_empty() => {
                        return Err(io_err(format!("AnyTLS: {}", String::from_utf8_lossy(&data))));
                    }
                    CMD_ALERT => return Err(io_err(format!("AnyTLS: {}", String::from_utf8_lossy(&data)))),
                    CMD_HEART_REQ => {}
                    _ => {}
                }
            }
        };
        tokio::pin!(up);
        tokio::pin!(down);
        tokio::select! {
            r = &mut up => match r {
                // Приложение закончило отправку. Полузакрытия в AnyTLS нет (FIN закрывает поток целиком),
            // поэтому, как в обычной пересылке, дочитываем ответ, пока он идёт, и только потом FIN.
                Ok(_) if uot => Ok(End::Clean),
                Ok(_) => loop {
                    if last_rx.load(Ordering::Relaxed) < up_done_at.load(Ordering::Relaxed) {
                        last_rx.store(up_done_at.load(Ordering::Relaxed), Ordering::Relaxed);
                    }
                    tokio::select! {
                        r = &mut down => break r.map(|_| End::Clean),
                        _ = tokio::time::sleep(Duration::from_millis(250)) => {
                            let idle = started.elapsed().as_millis() as u64 - last_rx.load(Ordering::Relaxed);
                            if idle > crate::common::HALF_CLOSE_TIMEOUT_SECS * 1000 {
                                break Ok(End::Clean);
                            }
                        }
                    }
                },
                Err(e) => Err(e),
            },
            r = &mut down => {
                stop.notify_one();
                // даём отправке дописать начатый кадр
                let up_done = tokio::time::timeout(Duration::from_secs(5), &mut up).await;
                match (r, up_done) {
                    (Ok(()), Ok(Ok(_))) => Ok(End::Clean),
                    (Ok(()), _) => Ok(End::Dead),
                    (Err(e), _) => Err(e),
                }
            }
        }
    };
    let _ = aw.shutdown().await;
    match outcome {
        Ok(End::Clean) => {
            let mut f = Vec::new();
            frame(CMD_FIN, sid, &[], &mut f);
            match tokio::time::timeout(Duration::from_secs(5), w.write_all(&f)).await {
                Ok(Ok(())) => Ok(End::Clean),
                _ => Ok(End::Dead),
            }
        }
        other => other,
    }
}

async fn open(p: &Profile, app: BoxStream, target: &Address, uot_dest: Option<&Address>) -> io::Result<()> {
    let key = pool_key(p);
    let open_frames = |sid: u32| {
        let mut out = Vec::with_capacity(96);
        frame(CMD_SYN, sid, &[], &mut out);
        let mut addr = Vec::new();
        target.write_socks(&mut addr);
        if let Some(d) = uot_dest {
            // запрос UoT v2: isConnect = 1 и адрес назначения
            addr.push(1);
            d.write_socks(&mut addr);
        }
        frame(CMD_PSH, sid, &addr, &mut out);
        out
    };
    // сессия из пула могла умереть незаметно: тогда открываем новую
    let mut sess = None;
    if let Some(mut s) = take_idle(&key) {
        let sid = s.next_sid;
        if s.w.write_all(&open_frames(sid)).await.is_ok() {
            log::debug!("AnyTLS {}: поток {sid} в уже открытой сессии", p.address);
            sess = Some(s);
        }
    }
    let mut sess = match sess {
        Some(s) => s,
        None => {
            let mut s = new_session(p).await?;
            let sid = s.next_sid;
            s.w.write_all(&open_frames(sid)).await?;
            s
        }
    };
    let sid = sess.next_sid;
    sess.next_sid += 1;
    match run_stream(&mut sess, sid, app, uot_dest.is_some()).await {
        Ok(End::Clean) => {
            put_idle(key, sess);
            Ok(())
        }
        Ok(End::Dead) => Ok(()),
        Err(e) => Err(e),
    }
}

pub async fn tcp(p: &Profile, app: BoxStream, dest: &Address) -> io::Result<()> {
    open(p, app, dest, None).await
}

pub async fn udp(p: &Profile, app: BoxStream, dest: &Address) -> io::Result<()> {
    open(p, app, &Address::new_domain(UOT_MAGIC, 0), Some(dest)).await
}
