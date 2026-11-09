//! Обработка трафика из TUN: TCP/UDP-потоки userspace-стека, DNS, сниффинг, маршрутизация.

pub mod device;
pub mod dns;
pub mod sniff;

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::common::{Address, BoxStream, CountingStream, Network, PrefixedStream, Stats};
use crate::config::{OutboundTag, Settings};
use crate::proxy::Outbound;
use crate::route::{Decision, DomainSet, Meta, Router};

/// Возможности платформы, нужные ядру (на Android — через JNI).
pub trait PlatformHooks: Send + Sync {
    /// UID приложения-владельца соединения (Android 10+: getConnectionOwnerUid).
    fn owner_uid(&self, tcp: bool, src: SocketAddr, dst: SocketAddr) -> Option<u32>;
    /// UID установленного приложения по имени пакета.
    fn package_uid(&self, package: &str) -> Option<u32>;
}

/// Маршрут на отдельный сервер в рабочем виде.
pub struct SplitRt {
    pub id: String,
    pub name: String,
    /// None — сервер удалён
    pub outbound: Option<Outbound>,
    pub fallback_main: bool,
    /// appId (uid % 100000) выбранных приложений
    pub app_ids: HashSet<u32>,
    pub domains: Option<DomainSet>,
    up: AtomicBool,
}

impl SplitRt {
    pub fn new(
        id: String,
        name: String,
        outbound: Option<Outbound>,
        fallback_main: bool,
        app_ids: HashSet<u32>,
        domains: Option<DomainSet>,
    ) -> Self {
        let up = AtomicBool::new(outbound.is_some());
        Self { id, name, outbound, fallback_main, app_ids, domains, up }
    }
    /// Сервер отвечает (проверяется в фоне).
    pub fn is_up(&self) -> bool {
        self.outbound.is_some() && self.up.load(Ordering::Relaxed)
    }
    pub fn set_up(&self, v: bool) {
        self.up.store(v, Ordering::Relaxed);
    }
}

/// Что делать с соединением, подпавшим под маршрут на отдельный сервер.
pub enum SplitDecision<'a> {
    /// Идём через сервер маршрута
    Via(&'a SplitRt),
    /// Сервер недоступен и включён запасной путь — обычные правила
    Fallback,
    /// Сервер недоступен — не пускаем (без утечек)
    Block(&'a SplitRt),
}

/// Общий контекст работающего ядра.
pub struct Ctx {
    pub router: Router,
    pub proxy: Outbound,
    pub fake: dns::FakeDns,
    pub settings: Settings,
    pub stats: Arc<Stats>,
    /// Маршруты на отдельные серверы — проверяются раньше обычных правил
    pub splits: Vec<SplitRt>,
    pub hooks: Option<Arc<dyn PlatformHooks>>,
    dns_cache: Mutex<HashMap<String, (IpAddr, Instant)>>,
}

impl Ctx {
    pub fn new(router: Router, proxy: Outbound, settings: Settings, stats: Arc<Stats>) -> Self {
        Self {
            router,
            proxy,
            fake: dns::FakeDns::new(),
            settings,
            stats,
            splits: Vec::new(),
            hooks: None,
            dns_cache: Mutex::new(HashMap::new()),
        }
    }

    /// Какой маршрут на отдельный сервер подходит соединению (если есть).
    pub fn match_split(&self, uid: Option<u32>, domain: Option<&str>, ip: Option<IpAddr>) -> Option<SplitDecision<'_>> {
        let by_app_ok = !ip.map(crate::common::is_private_ip).unwrap_or(false);
        let sp = self.splits.iter().find(|sp| {
            (by_app_ok && uid.map(|u| sp.app_ids.contains(&(u % 100_000))).unwrap_or(false))
                || matches!((domain, &sp.domains), (Some(d), Some(set)) if set.matches(d))
        })?;
        Some(if sp.is_up() {
            SplitDecision::Via(sp)
        } else if sp.fallback_main {
            SplitDecision::Fallback
        } else {
            SplitDecision::Block(sp)
        })
    }

    fn has_app_splits(&self) -> bool {
        self.hooks.is_some() && self.splits.iter().any(|s| !s.app_ids.is_empty())
    }

    /// UID владельца соединения; только для потоков из TUN.
    fn owner_uid(&self, tcp: bool, src: &str, dst: &Address) -> Option<u32> {
        if !self.has_app_splits() {
            return None;
        }
        let src: SocketAddr = src.parse().ok()?;
        if src.ip().is_loopback() {
            return None;
        }
        let dst = SocketAddr::new(dst.ip()?, dst.port);
        self.hooks.as_ref()?.owner_uid(tcp, src, dst)
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
        let uid = self.owner_uid(true, &src, &dest);
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
        let shown = match (&domain, dest.domain()) {
            (Some(d), None) => format!("{dest} ({d})"),
            _ => dest.to_string(),
        };
        let (tag, ob, rule) = match self.match_split(uid, domain.as_deref(), dest.ip()) {
            Some(SplitDecision::Via(sp)) => {
                (OutboundTag::Proxy, sp.outbound.clone().unwrap_or(Outbound::Block), format!("отдельный сервер «{}»", sp.name))
            }
            Some(SplitDecision::Block(sp)) => {
                log::info!("tcp {src} → {shown} [block] ← сервер «{}» недоступен", sp.name);
                return;
            }
            _ => {
                let (tag, rule) = self.decide(domain.as_deref(), dest.ip(), dest.port, Network::Tcp, proto).await;
                (tag, self.outbound(tag), rule)
            }
        };
        log::info!("tcp {src} → {shown} [{}] ← {rule}", tag.label());
        let app: BoxStream = if tag == OutboundTag::Proxy { Box::new(CountingStream::new(app, self.stats.clone())) } else { app };
        if let Err(e) = ob.handle_tcp(app, &dest).await {
            log::warn!("tcp {shown} [{}]: {e}", tag.label());
        }
    }

    pub async fn handle_udp(self: Arc<Self>, src: String, mut app: BoxStream, mut dest: Address) {
        let uid = if dest.port == 53 { None } else { self.owner_uid(false, &src, &dest) };
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
        let (tag, ob, rule) = match self.match_split(uid, domain.as_deref(), dest.ip()) {
            Some(SplitDecision::Via(sp)) => {
                (OutboundTag::Proxy, sp.outbound.clone().unwrap_or(Outbound::Block), format!("отдельный сервер «{}»", sp.name))
            }
            Some(SplitDecision::Block(sp)) => {
                log::info!("udp {src} → {dest} [block] ← сервер «{}» недоступен", sp.name);
                return;
            }
            _ => {
                let (tag, rule) = self.decide(domain.as_deref(), dest.ip(), dest.port, Network::Udp, None).await;
                (tag, self.outbound(tag), rule)
            }
        };
        log::info!("udp {src} → {dest} [{}] ← {rule}", tag.label());
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Profile, RoutingConfig};
    use std::path::Path;

    struct Hooks;
    impl PlatformHooks for Hooks {
        fn owner_uid(&self, _tcp: bool, src: SocketAddr, _dst: SocketAddr) -> Option<u32> {
            // порт источника 40000 — приложение с appId 10123 (второй пользователь профиля)
            (src.port() == 40000).then_some(10 * 100_000 + 10123)
        }
        fn package_uid(&self, package: &str) -> Option<u32> {
            (package == "com.openai.chatgpt").then_some(10123)
        }
    }

    fn ctx(fallback_main: bool) -> Ctx {
        let proxy = Outbound::Proxy(Arc::new(Profile { id: "main".into(), ..Default::default() }));
        let mut c = Ctx::new(Router::new(&RoutingConfig::default(), Path::new("/nonexistent")), proxy, Settings::default(), Arc::new(Stats::default()));
        let sets = crate::route::compile_domain_sets(&[&["domain:openai.com".to_string(), "keyword:gemini".to_string()]], Path::new("/nonexistent"));
        let dm = sets.into_iter().next();
        let server = Outbound::Proxy(Arc::new(Profile { id: "us".into(), ..Default::default() }));
        c.splits.push(SplitRt::new("s1".into(), "Нейросети".into(), Some(server), fallback_main, HashSet::from([10123]), dm));
        c.hooks = Some(Arc::new(Hooks));
        c
    }

    fn kind(d: Option<SplitDecision>) -> &'static str {
        match d {
            None => "none",
            Some(SplitDecision::Via(_)) => "via",
            Some(SplitDecision::Fallback) => "fallback",
            Some(SplitDecision::Block(_)) => "block",
        }
    }

    #[test]
    fn split_by_domain_and_app() {
        let c = ctx(false);
        assert_eq!(kind(c.match_split(None, Some("chat.openai.com"), None)), "via");
        assert_eq!(kind(c.match_split(None, Some("gemini.google.com"), None)), "via");
        assert_eq!(kind(c.match_split(None, Some("example.com"), None)), "none");
        // приложение из другого профиля пользователя — сравниваем по appId
        assert_eq!(kind(c.match_split(Some(10 * 100_000 + 10123), Some("example.com"), None)), "via");
        assert_eq!(kind(c.match_split(Some(10124), Some("example.com"), None)), "none");
        // локальная сеть из приложения идёт по обычным правилам
        assert_eq!(kind(c.match_split(Some(10123), None, Some("192.168.1.10".parse().unwrap()))), "none");
        assert_eq!(kind(c.match_split(Some(10123), None, Some("8.8.8.8".parse().unwrap()))), "via");
    }

    #[test]
    fn split_server_down() {
        let c = ctx(false);
        c.splits[0].set_up(false);
        assert_eq!(kind(c.match_split(None, Some("openai.com"), None)), "block");
        let c = ctx(true);
        c.splits[0].set_up(false);
        assert_eq!(kind(c.match_split(None, Some("openai.com"), None)), "fallback");
    }

    #[test]
    fn owner_uid_lookup() {
        let c = ctx(false);
        let dst = Address::from_socket("1.2.3.4:443".parse().unwrap());
        assert_eq!(c.owner_uid(true, "10.0.0.2:40000", &dst), Some(10 * 100_000 + 10123));
        assert_eq!(c.owner_uid(true, "10.0.0.2:40001", &dst), None);
        // SOCKS-вход (loopback) не опрашиваем
        assert_eq!(c.owner_uid(true, "127.0.0.1:40000", &dst), None);
    }
}
