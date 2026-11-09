//! Обработка трафика из TUN: TCP/UDP-потоки userspace-стека, DNS, сниффинг, маршрутизация.

pub mod device;
pub mod dns;
pub mod sniff;

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::common::{Address, BoxStream, CountingStream, Network, PrefixedStream, Stats};
use crate::config::{OutboundTag, Settings};
use crate::proxy::Outbound;
use crate::route::{Decision, Meta, Router};

/// Общий контекст работающего ядра.
pub struct Ctx {
    pub router: Router,
    pub proxy: Outbound,
    pub fake: dns::FakeDns,
    pub settings: Settings,
    pub stats: Arc<Stats>,
    dns_cache: Mutex<HashMap<String, (IpAddr, Instant)>>,
}

impl Ctx {
    pub fn new(router: Router, proxy: Outbound, settings: Settings, stats: Arc<Stats>) -> Self {
        Self { router, proxy, fake: dns::FakeDns::new(), settings, stats, dns_cache: Mutex::new(HashMap::new()) }
    }

    async fn resolve(&self, domain: &str) -> Option<IpAddr> {
        if let Some((ip, t)) = self.dns_cache.lock().get(domain) {
            if t.elapsed() < Duration::from_secs(120) {
                return Some(*ip);
            }
        }
        let fut = tokio::net::lookup_host((domain, 0));
        let ip = match tokio::time::timeout(Duration::from_secs(3), fut).await {
            Ok(Ok(mut it)) => {
                let all: Vec<SocketAddr> = it.by_ref().collect();
                all.iter().find(|a| a.is_ipv4()).or(all.first()).map(|a| a.ip())
            }
            _ => None,
        }?;
        let mut c = self.dns_cache.lock();
        if c.len() > 4096 {
            c.clear();
        }
        c.insert(domain.to_string(), (ip, Instant::now()));
        Some(ip)
    }

    /// Выбор исходящего соединения.
    pub async fn decide(&self, domain: Option<&str>, ip: Option<IpAddr>, port: u16, net: Network, proto: Option<&str>) -> (OutboundTag, String) {
        let mut meta = Meta { domain, ip, port, network: net, protocol: proto };
        match self.router.route(&meta) {
            Decision::Tag(t, r) => (t, r),
            Decision::NeedIp => {
                meta.ip = match domain {
                    Some(d) => self.resolve(d).await,
                    None => None,
                };
                if meta.ip.is_none() {
                    // не удалось разрешить — повторно без IP-правил
                    return (self.router.final_tag, "по умолчанию (DNS не ответил)".into());
                }
                match self.router.route(&meta) {
                    Decision::Tag(t, r) => (t, r),
                    Decision::NeedIp => (self.router.final_tag, "по умолчанию".into()),
                }
            }
        }
    }

    pub fn outbound(&self, tag: OutboundTag) -> Outbound {
        match tag {
            OutboundTag::Proxy => self.proxy.clone(),
            OutboundTag::Direct => Outbound::Direct,
            OutboundTag::Block => Outbound::Block,
        }
    }

    /// Обработка TCP-соединения: dest — исходный адрес назначения.
    pub async fn handle_tcp(self: Arc<Self>, src: String, mut app: BoxStream, mut dest: Address) {
        let mut domain: Option<String> = dest.domain().map(|s| s.to_string());
        if let Some(ip) = dest.ip() {
            if dns::is_fake(ip) {
                match self.fake.lookup(ip) {
                    Some(d) => {
                        dest = Address::new_domain(d.clone(), dest.port);
                        domain = Some(d);
                    }
                    None => {
                        log::debug!("tcp {src} → {dest}: неизвестный fake-IP, сброс");
                        return;
                    }
                }
            }
        }
        let mut proto: Option<&'static str> = None;
        if self.settings.sniffing {
            let mut buf = vec![0u8; 4096];
            if let Ok(Ok(n)) = tokio::time::timeout(Duration::from_millis(250), app.read(&mut buf)).await {
                buf.truncate(n);
                if let Some((p, host)) = sniff::sniff(&buf) {
                    proto = Some(p);
                    if domain.is_none() {
                        domain = host.filter(|h| h.parse::<IpAddr>().is_err());
                    }
                }
                app = Box::new(PrefixedStream::new(buf, app));
            }
        }
        let (tag, rule) = self.decide(domain.as_deref(), dest.ip(), dest.port, Network::Tcp, proto).await;
        let shown = match (&domain, dest.domain()) {
            (Some(d), None) => format!("{dest} ({d})"),
            _ => dest.to_string(),
        };
        log::info!("tcp {src} → {shown} [{}] ← {rule}", tag.label());
        let ob = self.outbound(tag);
        let app: BoxStream = if tag == OutboundTag::Proxy { Box::new(CountingStream::new(app, self.stats.clone())) } else { app };
        if let Err(e) = ob.handle_tcp(app, &dest).await {
            log::warn!("tcp {shown} [{}]: {e}", tag.label());
        }
    }

    pub async fn handle_udp(self: Arc<Self>, src: String, mut app: BoxStream, mut dest: Address) {
        if dest.port == 53 {
            if self.settings.fake_dns {
                self.serve_dns(app).await;
                return;
            }
            dest = Address::new_domain(self.settings.dns_server.clone(), 53);
        }
        let mut domain = None;
        if let Some(ip) = dest.ip() {
            if dns::is_fake(ip) {
                match self.fake.lookup(ip) {
                    Some(d) => {
                        dest = Address::new_domain(d.clone(), dest.port);
                        domain = Some(d);
                    }
                    None => return,
                }
            }
        }
        if self.settings.block_quic && dest.port == 443 {
            return;
        }
        let (tag, rule) = self.decide(domain.as_deref(), dest.ip(), dest.port, Network::Udp, None).await;
        log::info!("udp {src} → {dest} [{}] ← {rule}", tag.label());
        let ob = self.outbound(tag);
        if tag == OutboundTag::Proxy {
            app = Box::new(CountingStream::new(app, self.stats.clone()));
        }
        if let Err(e) = ob.handle_udp(app, &dest).await {
            log::warn!("udp {dest} [{}]: {e}", tag.label());
        }
    }

    async fn serve_dns(&self, mut app: BoxStream) {
        let mut buf = vec![0u8; 4096];
        loop {
            let n = match tokio::time::timeout(Duration::from_secs(30), app.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => n,
                _ => break,
            };
            let q = &buf[..n];
            let resp = match self.fake.answer(q) {
                Some(r) => {
                    if let Some((name, t, _)) = dns::parse_question(q) {
                        log::debug!("dns {name} (type {t}) → fake");
                    }
                    Some(r)
                }
                None => forward_dns(q, &self.settings.dns_server).await,
            };
            if let Some(r) = resp {
                if app.write_all(&r).await.is_err() {
                    break;
                }
            }
        }
    }
}

async fn forward_dns(q: &[u8], server: &str) -> Option<Vec<u8>> {
    let addr: SocketAddr = format!("{server}:53").parse().ok().or_else(|| server.parse().ok())?;
    let bind = if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let s = tokio::net::UdpSocket::bind(bind).await.ok()?;
    s.send_to(q, addr).await.ok()?;
    let mut b = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(Duration::from_secs(4), s.recv_from(&mut b)).await.ok()?.ok()?;
    b.truncate(n);
    Some(b)
}

/// Основной цикл: принимает потоки из ipstack и раздаёт обработчикам.
pub async fn run_tun(ctx: Arc<Ctx>, fd: i32, mtu: u16) -> io::Result<()> {
    let dev = device::TunDevice::from_fd(fd)?;
    let mut cfg = ipstack::IpStackConfig::default();
    cfg.mtu_unchecked(mtu);
    cfg.udp_timeout(Duration::from_secs(60));
    let mut stack = ipstack::IpStack::new(cfg, dev);
    log::info!("TUN запущен (MTU {mtu})");
    loop {
        let s = match stack.accept().await {
            Ok(s) => s,
            Err(e) => {
                log::error!("ipstack: {e}");
                return Err(io::Error::other(e.to_string()));
            }
        };
        match s {
            ipstack::IpStackStream::Tcp(t) => {
                let src = t.local_addr().to_string();
                let dest = Address::from_socket(t.peer_addr());
                tokio::spawn(ctx.clone().handle_tcp(src, Box::new(t), dest));
            }
            ipstack::IpStackStream::Udp(u) => {
                let src = u.local_addr().to_string();
                let dest = Address::from_socket(u.peer_addr());
                tokio::spawn(ctx.clone().handle_udp(src, Box::new(u), dest));
            }
            _ => {}
        }
    }
}

/// Локальный SOCKS5-вход (127.0.0.1:port) — как socks-inbound в v2rayNG.
pub async fn run_socks(ctx: Arc<Ctx>, listen: SocketAddr) -> io::Result<()> {
    let l = tokio::net::TcpListener::bind(listen).await?;
    log::info!("SOCKS5 слушает {listen}");
    loop {
        let (mut s, peer) = l.accept().await?;
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let r: io::Result<()> = async {
                let mut h = [0u8; 2];
                s.read_exact(&mut h).await?;
                let mut m = vec![0u8; h[1] as usize];
                s.read_exact(&mut m).await?;
                s.write_all(&[5, 0]).await?;
                let mut req = [0u8; 3];
                s.read_exact(&mut req).await?;
                let dest = Address::read_socks(&mut s).await?;
                if req[1] != 1 {
                    s.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
                    return Ok(());
                }
                s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
                ctx.handle_tcp(peer.to_string(), Box::new(s), dest).await;
                Ok(())
            }
            .await;
            if let Err(e) = r {
                log::debug!("socks {peer}: {e}");
            }
        });
    }
}
