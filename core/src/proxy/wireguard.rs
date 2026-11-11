//! WireGuard: шифрование — boringtun (Noise IK), а поверх туннеля — собственный TCP/IP-стек
//! (smoltcp), потому что WireGuard переносит IP-пакеты, а не потоки. Один туннель на профиль,
//! им управляет одна задача; соединения общаются с ней через каналы.
//! Поддерживаются reserved (Cloudflare WARP), pre-shared key, IPv4 и IPv6 внутри туннеля.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use boringtun::noise::{Tunn, TunnResult};
use parking_lot::Mutex;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{self, Device, DeviceCapabilities, Medium};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address, Ipv6Address};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, Notify};

use crate::common::{io_err, Address, BoxStream, Host};
use crate::config::Profile;

const DEFAULT_MTU: usize = 1280;
const TCP_BUF: usize = 256 * 1024;
const DNS_TTL: Duration = Duration::from_secs(300);

// ───────────────────────── разбор параметров ─────────────────────────

/// Ключ WireGuard: base64 (как в конфигурации wg) или hex.
pub fn parse_key(s: &str) -> io::Result<[u8; 32]> {
    let s = s.trim();
    let raw = if s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        (0..32).map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap()).collect()
    } else {
        crate::links::b64_decode(s).unwrap_or_default()
    };
    raw.try_into().map_err(|_| io_err("WireGuard: неверный ключ (нужно 32 байта в base64)"))
}

/// reserved: "1,2,3" или base64 от трёх байт; пусто — нули.
pub fn parse_reserved(s: &str) -> io::Result<[u8; 3]> {
    let s = s.trim().trim_matches(|c| c == '[' || c == ']');
    if s.is_empty() {
        return Ok([0; 3]);
    }
    if s.contains(',') {
        let v: Vec<u8> = s.split(',').filter_map(|x| x.trim().parse().ok()).collect();
        return v.try_into().map_err(|_| io_err("WireGuard: reserved — три числа 0–255"));
    }
    crate::links::b64_decode(s)
        .and_then(|v| <[u8; 3]>::try_from(v).ok())
        .ok_or_else(|| io_err("WireGuard: reserved — три числа через запятую или base64"))
}

/// "10.0.0.2/32, fd00::2" → адреса интерфейса.
pub fn parse_addresses(s: &str) -> io::Result<Vec<IpCidr>> {
    let mut out = Vec::new();
    for part in s.split(',').map(|x| x.trim()).filter(|x| !x.is_empty()) {
        let ip: IpAddr = part.split('/').next().unwrap_or("").parse().map_err(|_| io_err(format!("WireGuard: неверный адрес {part}")))?;
        out.push(match ip {
            IpAddr::V4(v4) => IpCidr::new(IpAddress::Ipv4(v4), 32),
            IpAddr::V6(v6) => IpCidr::new(IpAddress::Ipv6(v6), 128),
        });
    }
    if out.is_empty() {
        return Err(io_err("WireGuard: не указан адрес интерфейса"));
    }
    Ok(out)
}

// ───────────────────────── виртуальное устройство ─────────────────────────

struct VirtDevice {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
    mtu: usize,
}

struct RxTok(Vec<u8>);
struct TxTok<'a>(&'a mut VecDeque<Vec<u8>>);

impl phy::RxToken for RxTok {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl phy::TxToken for TxTok<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut v = vec![0u8; len];
        let r = f(&mut v);
        self.0.push_back(v);
        r
    }
}

impl Device for VirtDevice {
    type RxToken<'a> = RxTok;
    type TxToken<'a> = TxTok<'a>;
    fn receive(&mut self, _: SmolInstant) -> Option<(RxTok, TxTok<'_>)> {
        let pkt = self.rx.pop_front()?;
        Some((RxTok(pkt), TxTok(&mut self.tx)))
    }
    fn transmit(&mut self, _: SmolInstant) -> Option<TxTok<'_>> {
        Some(TxTok(&mut self.tx))
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.medium = Medium::Ip;
        c.max_transmission_unit = self.mtu;
        c
    }
}

// ───────────────────────── туннель ─────────────────────────

enum Cmd {
    Tcp { dest: SocketAddr, to_app: mpsc::Sender<Vec<u8>>, from_app: mpsc::Receiver<Vec<u8>>, ready: oneshot::Sender<io::Result<()>> },
    Udp { dest: SocketAddr, to_app: mpsc::Sender<Vec<u8>>, from_app: mpsc::Receiver<Vec<u8>> },
}

struct Conn {
    handle: SocketHandle,
    udp_dest: Option<IpEndpoint>,
    to_app: Option<mpsc::Sender<Vec<u8>>>,
    from_app: mpsc::Receiver<Vec<u8>>,
    pending: Option<(Vec<u8>, usize)>,
    app_done: bool,
    ready: Option<oneshot::Sender<io::Result<()>>>,
}

struct Tunnel {
    cmd: mpsc::UnboundedSender<Cmd>,
    wake: Arc<Notify>,
    closed: Arc<AtomicBool>,
    /// Рукопожатие с сервером состоялось
    up: Arc<AtomicBool>,
    up_notify: Arc<Notify>,
    has_v4: bool,
    has_v6: bool,
    dns: Mutex<HashMap<String, (IpAddr, Instant)>>,
}

fn tunnels() -> &'static tokio::sync::Mutex<HashMap<String, Arc<Tunnel>>> {
    static T: OnceLock<tokio::sync::Mutex<HashMap<String, Arc<Tunnel>>>> = OnceLock::new();
    T.get_or_init(Default::default)
}

pub fn reset() {
    if let Ok(mut m) = tunnels().try_lock() {
        for (_, t) in m.drain() {
            t.closed.store(true, Ordering::Relaxed);
            t.wake.notify_one();
        }
    }
}

struct Driver {
    sock: UdpSocket,
    tunn: Tunn,
    reserved: [u8; 3],
    dev: VirtDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    conns: Vec<Conn>,
    next_port: u16,
    start: Instant,
    out: Vec<u8>,
    up: Arc<AtomicBool>,
    up_notify: Arc<Notify>,
}

impl Driver {
    fn now(&self) -> SmolInstant {
        SmolInstant::from_millis(self.start.elapsed().as_millis() as i64)
    }

    /// Отправка пакета WireGuard серверу; reserved вписывается в байты 1–3 заголовка.
    fn send_wire(sock: &UdpSocket, reserved: [u8; 3], pkt: &mut [u8]) {
        if pkt.len() >= 4 && reserved != [0; 3] {
            pkt[1..4].copy_from_slice(&reserved);
        }
        // очередь сокета переполнена — пакет теряется, как и положено UDP
        let _ = sock.try_send(pkt);
    }

    fn flush_tx(&mut self) {
        while let Some(pkt) = self.dev.tx.pop_front() {
            if let TunnResult::WriteToNetwork(d) = self.tunn.encapsulate(&pkt, &mut self.out) {
                Self::send_wire(&self.sock, self.reserved, d);
            }
        }
    }

    fn on_datagram(&mut self, data: &mut [u8]) {
        if data.len() >= 4 {
            data[1..4].fill(0);
        }
        let mut input: &[u8] = data;
        loop {
            match self.tunn.decapsulate(None, input, &mut self.out) {
                TunnResult::WriteToNetwork(d) => {
                    Self::send_wire(&self.sock, self.reserved, d);
                    // после ответа на рукопожатие нужно вытолкнуть пакеты, ждавшие сессию
                    input = &[];
                    continue;
                }
                TunnResult::WriteToTunnelV4(p, _) | TunnResult::WriteToTunnelV6(p, _) => self.dev.rx.push_back(p.to_vec()),
                TunnResult::Done => {}
                TunnResult::Err(e) => log::debug!("WireGuard: {e:?}"),
            }
            break;
        }
        if !self.up.load(Ordering::Relaxed) && self.tunn.stats().0.is_some() {
            self.up.store(true, Ordering::Relaxed);
            self.up_notify.notify_waiters();
        }
    }

    fn timers(&mut self) {
        match self.tunn.update_timers(&mut self.out) {
            TunnResult::WriteToNetwork(d) => Self::send_wire(&self.sock, self.reserved, d),
            TunnResult::Err(e) => log::debug!("WireGuard: {e:?}"),
            _ => {}
        }
    }

    fn local_port(&mut self) -> u16 {
        self.next_port = if self.next_port >= 65000 { 20000 } else { self.next_port + 1 };
        self.next_port
    }

    fn add(&mut self, cmd: Cmd) {
        match cmd {
            Cmd::Tcp { dest, to_app, from_app, ready } => {
                let mut s = tcp::Socket::new(tcp::SocketBuffer::new(vec![0u8; TCP_BUF]), tcp::SocketBuffer::new(vec![0u8; TCP_BUF]));
                s.set_nagle_enabled(false);
                s.set_congestion_control(tcp::CongestionControl::Cubic);
                s.set_keep_alive(Some(smoltcp::time::Duration::from_secs(45)));
                s.set_timeout(Some(smoltcp::time::Duration::from_secs(90)));
                let port = self.local_port();
                if let Err(e) = s.connect(self.iface.context(), (IpAddress::from(dest.ip()), dest.port()), port) {
                    let _ = ready.send(Err(io_err(format!("WireGuard: {e}"))));
                    return;
                }
                let handle = self.sockets.add(s);
                self.conns.push(Conn { handle, udp_dest: None, to_app: Some(to_app), from_app, pending: None, app_done: false, ready: Some(ready) });
            }
            Cmd::Udp { dest, to_app, from_app } => {
                let buf = || udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 64], vec![0u8; 128 * 1024]);
                let mut s = udp::Socket::new(buf(), buf());
                let port = self.local_port();
                if s.bind(port).is_err() {
                    return;
                }
                let handle = self.sockets.add(s);
                let ep = IpEndpoint::new(IpAddress::from(dest.ip()), dest.port());
                self.conns.push(Conn { handle, udp_dest: Some(ep), to_app: Some(to_app), from_app, pending: None, app_done: false, ready: None });
            }
        }
    }

    /// Перекладывает данные между сокетами стека и каналами соединений. true — что-то сдвинулось.
    fn service(&mut self) -> bool {
        let mut progress = false;
        let mut i = 0;
        while i < self.conns.len() {
            let c = &mut self.conns[i];
            let remove = match c.udp_dest {
                Some(dest) => {
                    let s = self.sockets.get_mut::<udp::Socket>(c.handle);
                    while s.can_send() {
                        match c.from_app.try_recv() {
                            Ok(v) => {
                                let _ = s.send_slice(&v, dest);
                                progress = true;
                            }
                            Err(mpsc::error::TryRecvError::Empty) => break,
                            Err(mpsc::error::TryRecvError::Disconnected) => {
                                c.app_done = true;
                                break;
                            }
                        }
                    }
                    while s.can_recv() {
                        let Some(tx) = &c.to_app else { break };
                        match tx.try_reserve() {
                            Ok(permit) => {
                                if let Ok((d, _)) = s.recv() {
                                    permit.send(d.to_vec());
                                    progress = true;
                                }
                            }
                            Err(mpsc::error::TrySendError::Full(_)) => break,
                            Err(mpsc::error::TrySendError::Closed(_)) => {
                                c.app_done = true;
                                break;
                            }
                        }
                    }
                    c.app_done
                }
                None => {
                    let s = self.sockets.get_mut::<tcp::Socket>(c.handle);
                    if c.ready.is_some() {
                        if s.may_send() {
                            let _ = c.ready.take().unwrap().send(Ok(()));
                            progress = true;
                        } else if !s.is_open() {
                            let _ = c.ready.take().unwrap().send(Err(io_err("WireGuard: соединение не установлено (отказ или таймаут)")));
                        }
                    }
                    // приложение → сеть
                    while s.can_send() && !c.app_done {
                        if c.pending.is_none() {
                            match c.from_app.try_recv() {
                                Ok(v) => c.pending = Some((v, 0)),
                                Err(mpsc::error::TryRecvError::Empty) => break,
                                Err(mpsc::error::TryRecvError::Disconnected) => {
                                    c.app_done = true;
                                    s.close();
                                    progress = true;
                                    break;
                                }
                            }
                        }
                        let (v, off) = c.pending.as_mut().unwrap();
                        let n = s.send_slice(&v[*off..]).unwrap_or(0);
                        *off += n;
                        if *off >= v.len() {
                            c.pending = None;
                        }
                        if n == 0 {
                            break;
                        }
                        progress = true;
                    }
                    // сеть → приложение
                    let mut app_gone = false;
                    while s.can_recv() {
                        let Some(tx) = &c.to_app else {
                            s.abort();
                            break;
                        };
                        match tx.try_reserve() {
                            Ok(permit) => {
                                let data = s.recv(|b| {
                                    let n = b.len().min(32 * 1024);
                                    (n, b[..n].to_vec())
                                });
                                if let Ok(d) = data {
                                    permit.send(d);
                                    progress = true;
                                }
                            }
                            Err(mpsc::error::TrySendError::Full(_)) => break,
                            Err(mpsc::error::TrySendError::Closed(_)) => {
                                app_gone = true;
                                break;
                            }
                        }
                    }
                    if app_gone {
                        c.to_app = None;
                        s.abort();
                        progress = true;
                    }
                    // сервер закрыл свою сторону и всё прочитано — конец потока для приложения
                    if c.to_app.is_some() && c.ready.is_none() && !s.may_recv() && !s.can_recv() {
                        c.to_app = None;
                        progress = true;
                    }
                    // обработчик соединения исчез (ошибка, таймаут) — сокет больше не нужен
                    if c.to_app.as_ref().map(|t| t.is_closed()).unwrap_or(false) && c.ready.is_none() {
                        c.to_app = None;
                        s.abort();
                    }
                    !s.is_open() && c.ready.is_none() && (c.to_app.is_none() || !s.can_recv())
                }
            };
            if remove {
                let c = self.conns.swap_remove(i);
                self.sockets.remove(c.handle);
                progress = true;
            } else {
                i += 1;
            }
        }
        progress
    }

    async fn run(mut self, mut cmds: mpsc::UnboundedReceiver<Cmd>, wake: Arc<Notify>, closed: Arc<AtomicBool>) {
        let mut rbuf = vec![0u8; 65536];
        let mut last_timer = Instant::now();
        // первое рукопожатие — сразу, не дожидаясь данных; у нового сокета готовность к записи
        // ещё не известна, и try_send без этого ожидания молча потерял бы пакет
        let _ = self.sock.writable().await;
        if let TunnResult::WriteToNetwork(d) = self.tunn.format_handshake_initiation(&mut self.out, false) {
            Self::send_wire(&self.sock, self.reserved, d);
        }
        while !closed.load(Ordering::Relaxed) {
            for _ in 0..64 {
                let now = self.now();
                self.iface.poll(now, &mut self.dev, &mut self.sockets);
                self.flush_tx();
                if !self.service() && self.dev.rx.is_empty() {
                    break;
                }
            }
            let now = self.now();
            self.iface.poll(now, &mut self.dev, &mut self.sockets);
            self.flush_tx();
            let tick = Duration::from_millis(if self.conns.is_empty() { 1000 } else { 250 });
            let delay = self
                .iface
                .poll_delay(now, &self.sockets)
                .map(|d| Duration::from_micros(d.total_micros()))
                .unwrap_or(tick)
                .min(tick.saturating_sub(last_timer.elapsed()))
                .max(Duration::from_millis(1));
            tokio::select! {
                r = self.sock.recv(&mut rbuf) => {
                    match r {
                        Ok(n) => {
                            let mut d = rbuf[..n].to_vec();
                            self.on_datagram(&mut d);
                            // забираем всё, что уже пришло, одним заходом
                            for _ in 0..128 {
                                match self.sock.try_recv(&mut rbuf) {
                                    Ok(n) => {
                                        let mut d = rbuf[..n].to_vec();
                                        self.on_datagram(&mut d);
                                    }
                                    Err(_) => break,
                                }
                            }
                        }
                        // ICMP «порт недоступен» и подобное: сервер может появиться позже
                        Err(e) => {
                            log::debug!("WireGuard UDP: {e}");
                            tokio::time::sleep(Duration::from_millis(200)).await;
                        }
                    }
                }
                c = cmds.recv() => match c {
                    Some(c) => self.add(c),
                    None => break,
                },
                _ = wake.notified() => {}
                _ = tokio::time::sleep(delay) => {}
            }
            if last_timer.elapsed() >= tick {
                last_timer = Instant::now();
                self.timers();
            }
        }
        closed.store(true, Ordering::Relaxed);
    }
}

async fn get_tunnel(p: &Profile) -> io::Result<Arc<Tunnel>> {
    let key = crate::links::to_link(p);
    let tun = {
        let mut map = tunnels().lock().await;
        match map.get(&key) {
            Some(t) if !t.closed.load(Ordering::Relaxed) => t.clone(),
            _ => {
                let t = create(p).await?;
                map.insert(key.clone(), t.clone());
                t
            }
        }
    };
    // без рукопожатия данные всё равно не пойдут: ждём его и сообщаем понятную ошибку
    if !tun.up.load(Ordering::Relaxed) {
        let wait = async {
            while !tun.up.load(Ordering::Relaxed) {
                let n = tun.up_notify.notified();
                if tun.up.load(Ordering::Relaxed) {
                    break;
                }
                let _ = tokio::time::timeout(Duration::from_millis(200), n).await;
            }
        };
        if tokio::time::timeout(crate::transport::CONNECT_TIMEOUT, wait).await.is_err() {
            return Err(io_err("WireGuard: сервер не ответил на рукопожатие (проверьте ключи, адрес и reserved)"));
        }
    }
    Ok(tun)
}

async fn create(p: &Profile) -> io::Result<Arc<Tunnel>> {
    let private = parse_key(&p.id_or_password)?;
    let public = parse_key(&p.public_key)?;
    let psk = if p.secret.trim().is_empty() { None } else { Some(parse_key(&p.secret)?) };
    let reserved = parse_reserved(&p.reserved)?;
    let addrs = parse_addresses(&p.local_address)?;
    let mtu = if p.mtu >= 576 { p.mtu as usize } else { DEFAULT_MTU };

    let endpoint = crate::transport::server_addr(p).resolve().await?;
    let bind: SocketAddr = if endpoint.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }.parse().unwrap();
    let sock = UdpSocket::bind(bind).await?;
    sock.connect(endpoint).await?;
    // сервер шлёт данные пачками: маленький буфер приёма означает потери и повторы TCP
    let _ = socket2::SockRef::from(&sock).set_recv_buffer_size(2 << 20);

    let tunn = Tunn::new(
        boringtun::x25519::StaticSecret::from(private),
        boringtun::x25519::PublicKey::from(public),
        psk,
        Some(25),
        rand::random::<u32>() >> 8,
        None,
    );
    let mut dev = VirtDevice { rx: VecDeque::new(), tx: VecDeque::new(), mtu };
    let mut cfg = Config::new(HardwareAddress::Ip);
    cfg.random_seed = rand::random();
    let mut iface = Interface::new(cfg, &mut dev, SmolInstant::from_millis(0));
    let has_v4 = addrs.iter().any(|a| matches!(a.address(), IpAddress::Ipv4(_)));
    let has_v6 = addrs.iter().any(|a| matches!(a.address(), IpAddress::Ipv6(_)));
    iface.update_ip_addrs(|list| {
        for a in addrs.iter().take(list.capacity()) {
            let _ = list.push(*a);
        }
    });
    // в IP-среде шлюз не используется, но маршрут по умолчанию стеку нужен
    let _ = iface.routes_mut().add_default_ipv4_route(Ipv4Address::new(0, 0, 0, 1));
    let _ = iface.routes_mut().add_default_ipv6_route(Ipv6Address::new(0, 0, 0, 0, 0, 0, 0, 1));

    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    let wake = Arc::new(Notify::new());
    let closed = Arc::new(AtomicBool::new(false));
    let up = Arc::new(AtomicBool::new(false));
    let up_notify = Arc::new(Notify::new());
    let driver = Driver {
        sock,
        tunn,
        reserved,
        dev,
        iface,
        sockets: SocketSet::new(Vec::new()),
        conns: Vec::new(),
        next_port: 20000 + (rand::random::<u16>() % 20000),
        start: Instant::now(),
        out: vec![0u8; 65536 + 64],
        up: up.clone(),
        up_notify: up_notify.clone(),
    };
    tokio::spawn(driver.run(cmd_rx, wake.clone(), closed.clone()));
    Ok(Arc::new(Tunnel { cmd: cmd_tx, wake, closed, up, up_notify, has_v4, has_v6, dns: Mutex::new(HashMap::new()) }))
}

// ───────────────────────── DNS через туннель ─────────────────────────

fn dns_query(name: &str, qtype: u16, id: u16) -> Vec<u8> {
    let mut q = Vec::with_capacity(32 + name.len());
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.trim_end_matches('.').split('.') {
        let l = label.len().min(63);
        q.push(l as u8);
        q.extend_from_slice(&label.as_bytes()[..l]);
    }
    q.push(0);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&[0, 1]);
    q
}

fn skip_name(m: &[u8], mut p: usize) -> Option<usize> {
    loop {
        let l = *m.get(p)? as usize;
        if l == 0 {
            return Some(p + 1);
        }
        if l & 0xc0 == 0xc0 {
            return Some(p + 2);
        }
        p += 1 + l;
    }
}

/// Первый адрес нужного типа из ответа DNS.
fn dns_answer(m: &[u8], id: u16, qtype: u16) -> Option<IpAddr> {
    if m.len() < 12 || u16::from_be_bytes([m[0], m[1]]) != id {
        return None;
    }
    let qd = u16::from_be_bytes([m[4], m[5]]);
    let an = u16::from_be_bytes([m[6], m[7]]);
    let mut p = 12;
    for _ in 0..qd {
        p = skip_name(m, p)? + 4;
    }
    for _ in 0..an {
        p = skip_name(m, p)?;
        let t = u16::from_be_bytes([*m.get(p)?, *m.get(p + 1)?]);
        let len = u16::from_be_bytes([*m.get(p + 8)?, *m.get(p + 9)?]) as usize;
        let data = m.get(p + 10..p + 10 + len)?;
        if t == qtype {
            match (t, len) {
                (1, 4) => return Some(IpAddr::from(<[u8; 4]>::try_from(data).ok()?)),
                (28, 16) => return Some(IpAddr::from(<[u8; 16]>::try_from(data).ok()?)),
                _ => {}
            }
        }
        p += 10 + len;
    }
    None
}

impl Tunnel {
    fn open_udp(&self, dest: SocketAddr) -> io::Result<(mpsc::Sender<Vec<u8>>, mpsc::Receiver<Vec<u8>>)> {
        let (to_sock, from_app) = mpsc::channel(64);
        let (to_app, from_sock) = mpsc::channel(64);
        self.cmd.send(Cmd::Udp { dest, to_app, from_app }).map_err(|_| io_err("WireGuard: туннель закрыт"))?;
        self.wake.notify_one();
        Ok((to_sock, from_sock))
    }

    /// Адрес назначения: домены разрешаются через сам туннель, чтобы запрос не ушёл мимо.
    async fn resolve(&self, dest: &Address) -> io::Result<SocketAddr> {
        let name = match &dest.host {
            Host::Ip(ip) => {
                if (ip.is_ipv4() && !self.has_v4) || (ip.is_ipv6() && !self.has_v6) {
                    return Err(io_err("WireGuard: у туннеля нет адреса этого семейства (IPv4/IPv6)"));
                }
                return Ok(SocketAddr::new(*ip, dest.port));
            }
            Host::Domain(d) => d.to_ascii_lowercase(),
        };
        if let Some((ip, at)) = self.dns.lock().get(&name) {
            if at.elapsed() < DNS_TTL {
                return Ok(SocketAddr::new(*ip, dest.port));
            }
        }
        let server: SocketAddr = if self.has_v4 { "1.1.1.1:53" } else { "[2606:4700:4700::1111]:53" }.parse().unwrap();
        let qtype = if self.has_v4 { 1 } else { 28 };
        let (tx, mut rx) = self.open_udp(server)?;
        let id: u16 = rand::random();
        let q = dns_query(&name, qtype, id);
        for _ in 0..3 {
            tx.send(q.clone()).await.map_err(|_| io_err("WireGuard: туннель закрыт"))?;
            self.wake.notify_one();
            if let Ok(Some(resp)) = tokio::time::timeout(Duration::from_secs(2), rx.recv()).await {
                self.wake.notify_one();
                if let Some(ip) = dns_answer(&resp, id, qtype) {
                    let mut c = self.dns.lock();
                    if c.len() > 2048 {
                        c.clear();
                    }
                    c.insert(name, (ip, Instant::now()));
                    return Ok(SocketAddr::new(ip, dest.port));
                }
                return Err(io_err(format!("WireGuard: домен {name} не найден")));
            }
        }
        Err(io_err(format!("WireGuard: DNS не ответил ({name})")))
    }
}

// ───────────────────────── исходящие соединения ─────────────────────────

pub async fn tcp(p: &Profile, app: BoxStream, dest: &Address) -> io::Result<()> {
    let tun = get_tunnel(p).await?;
    let target = tun.resolve(dest).await?;
    let (to_sock, from_app) = mpsc::channel::<Vec<u8>>(16);
    let (to_app, mut from_sock) = mpsc::channel::<Vec<u8>>(16);
    let (ready_tx, ready_rx) = oneshot::channel();
    tun.cmd.send(Cmd::Tcp { dest: target, to_app, from_app, ready: ready_tx }).map_err(|_| io_err("WireGuard: туннель закрыт"))?;
    tun.wake.notify_one();
    match tokio::time::timeout(crate::transport::CONNECT_TIMEOUT, ready_rx).await {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(e))) => return Err(e),
        Ok(Err(_)) => return Err(io_err("WireGuard: туннель закрыт")),
        Err(_) => return Err(io::Error::new(io::ErrorKind::TimedOut, format!("WireGuard: таймаут подключения к {dest}"))),
    }
    let (mut ar, mut aw) = tokio::io::split(app);
    let (w1, w2) = (tun.wake.clone(), tun.wake.clone());
    let up = async move {
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            let n = ar.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            if to_sock.send(buf[..n].to_vec()).await.is_err() {
                break;
            }
            w1.notify_one();
        }
        drop(to_sock);
        w1.notify_one();
        Ok::<_, io::Error>(())
    };
    let down = async move {
        while let Some(v) = from_sock.recv().await {
            aw.write_all(&v).await?;
            w2.notify_one();
        }
        let _ = aw.shutdown().await;
        Ok::<_, io::Error>(())
    };
    let r = crate::common::join_halves(up, down).await;
    tun.wake.notify_one();
    r
}

pub async fn udp(p: &Profile, mut app: BoxStream, dest: &Address) -> io::Result<()> {
    let tun = get_tunnel(p).await?;
    let target = tun.resolve(dest).await?;
    let (tx, mut rx) = tun.open_udp(target)?;
    let mut buf = vec![0u8; 65536];
    loop {
        tokio::select! {
            r = app.read(&mut buf) => {
                let n = r?;
                if n == 0 { break; }
                // очередь переполнена — пакет теряется
                let _ = tx.try_send(buf[..n].to_vec());
                tun.wake.notify_one();
            }
            v = rx.recv() => match v {
                Some(v) => {
                    app.write_all(&v).await?;
                    tun.wake.notify_one();
                }
                None => break,
            },
            _ = tokio::time::sleep(super::UDP_IDLE) => break,
        }
    }
    drop(tx);
    tun.wake.notify_one();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn params() {
        let k = "YNXtAzepDqRv9H52osJVDQnznT5AM11eCK3ESpwSt04=";
        assert_eq!(parse_key(k).unwrap().len(), 32);
        assert!(parse_key("short").is_err());
        assert_eq!(parse_key(&"ab".repeat(32)).unwrap(), [0xab; 32]);
        assert_eq!(parse_reserved("1, 2,3").unwrap(), [1, 2, 3]);
        assert_eq!(parse_reserved("[7,8,9]").unwrap(), [7, 8, 9]);
        assert_eq!(parse_reserved("AQID").unwrap(), [1, 2, 3]);
        assert_eq!(parse_reserved("").unwrap(), [0, 0, 0]);
        assert!(parse_reserved("1,2").is_err());
        let a = parse_addresses("172.16.0.2/32, 2606:4700:110:8a36::1/128").unwrap();
        assert_eq!(a.len(), 2);
        assert!(parse_addresses("").is_err());
    }

    #[test]
    fn dns_messages() {
        let q = dns_query("example.com", 1, 0x1234);
        assert_eq!(&q[..2], &[0x12, 0x34]);
        // ответ: вопрос + CNAME + A
        let mut r = q.clone();
        r[2] = 0x81;
        r[3] = 0x80;
        r[7] = 2;
        r.extend_from_slice(&[0xc0, 0x0c, 0, 5, 0, 1, 0, 0, 0, 60, 0, 2, 0xc0, 0x0c]);
        r.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34]);
        assert_eq!(dns_answer(&r, 0x1234, 1), Some("93.184.216.34".parse().unwrap()));
        assert_eq!(dns_answer(&r, 0x1111, 1), None);
        assert_eq!(dns_answer(&r, 0x1234, 28), None);
    }
}
