//! Запуск/остановка ядра и тест задержки.

use std::io;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::common::{io_err, Address, Stats};
use crate::config::{AppConfig, Profile};
use crate::proxy::Outbound;
use crate::route::Router;
use crate::tun::{self, Ctx};

struct Running {
    rt: tokio::runtime::Runtime,
    stats: Arc<Stats>,
    profile: String,
    started: Instant,
}

static RUNNING: Mutex<Option<Running>> = Mutex::new(None);

/// Общий рантайм для фоновых задач UI (тесты задержки и т.п.).
pub fn shared_runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("xd-bg")
            .enable_all()
            .build()
            .expect("runtime")
    })
}

/// Запуск ядра. `tun_fd` — дескриптор от VpnService (None — только SOCKS-вход).
pub fn start(cfg: &AppConfig, geo_dir: &Path, tun_fd: Option<i32>) -> io::Result<()> {
    stop();
    let profile = cfg.selected_profile().cloned().ok_or_else(|| io_err("не выбран сервер"))?;
    let router = Router::new(&cfg.routing, geo_dir);
    let stats = Arc::new(Stats::default());
    let ctx = Arc::new(Ctx::new(router, Outbound::Proxy(Arc::new(profile.clone())), cfg.settings.clone(), stats.clone()));
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("xd-core")
        .enable_all()
        .build()?;
    log::info!("Запуск: {} ({}:{}, {})", profile.display_name(), profile.address, profile.port, profile.summary());
    if let Some(fd) = tun_fd {
        let c = ctx.clone();
        let mtu = cfg.settings.mtu;
        rt.spawn(async move {
            if let Err(e) = tun::run_tun(c, fd, mtu).await {
                log::error!("TUN остановлен: {e}");
            }
        });
    }
    if cfg.settings.local_socks || tun_fd.is_none() {
        let c = ctx.clone();
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], cfg.settings.socks_port));
        rt.spawn(async move {
            if let Err(e) = tun::run_socks(c, addr).await {
                log::error!("SOCKS-вход: {e}");
            }
        });
    }
    *RUNNING.lock() = Some(Running { rt, stats, profile: profile.display_name(), started: Instant::now() });
    Ok(())
}

pub fn stop() {
    if let Some(r) = RUNNING.lock().take() {
        r.rt.shutdown_timeout(Duration::from_millis(500));
        log::info!("Остановлено");
    }
}

pub fn is_running() -> bool {
    RUNNING.lock().is_some()
}

/// (отправлено, получено, имя профиля, секунд с запуска)
pub fn stats() -> Option<(u64, u64, String, u64)> {
    RUNNING.lock().as_ref().map(|r| {
        (r.stats.up.load(Ordering::Relaxed), r.stats.down.load(Ordering::Relaxed), r.profile.clone(), r.started.elapsed().as_secs())
    })
}

struct TestUrl {
    tls: bool,
    host: String,
    port: u16,
    path: String,
}

fn parse_test_url(u: &str) -> TestUrl {
    let (tls, rest) = if let Some(r) = u.strip_prefix("https://") {
        (true, r)
    } else {
        (false, u.strip_prefix("http://").unwrap_or(u))
    };
    let (hp, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };
    let (host, port) = match hp.rsplit_once(':') {
        Some((h, p)) if p.parse::<u16>().is_ok() => (h.to_string(), p.parse().unwrap()),
        _ => (hp.to_string(), if tls { 443 } else { 80 }),
    };
    TestUrl { tls, host, port, path }
}

/// "Настоящая" задержка: HTTP-запрос через сервер, время до первого ответа.
pub async fn delay_test(p: &Profile, url: &str) -> io::Result<u64> {
    let t = parse_test_url(url);
    let (client, server) = tokio::io::duplex(64 * 1024);
    let ob = Outbound::Proxy(Arc::new(p.clone()));
    let dest = Address::new_domain(t.host.clone(), t.port);
    let start = Instant::now();
    let task = tokio::spawn(async move { ob.handle_tcp(Box::new(server), &dest).await });
    let req = format!("HEAD {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: curl/8.5.0\r\nConnection: close\r\n\r\n", t.path, t.host);
    let fut = async {
        let mut head = [0u8; 12];
        if t.tls {
            let mut s = crate::transport::tls_connect(client, &t.host, "http/1.1", false).await?;
            s.write_all(req.as_bytes()).await?;
            s.read_exact(&mut head).await?;
        } else {
            let mut s = client;
            s.write_all(req.as_bytes()).await?;
            s.read_exact(&mut head).await?;
        }
        if !head.starts_with(b"HTTP/") {
            return Err(io_err("некорректный ответ"));
        }
        Ok::<_, io::Error>(())
    };
    let res = tokio::time::timeout(Duration::from_secs(10), fut).await;
    let elapsed = start.elapsed().as_millis() as u64;
    match res {
        Ok(Ok(())) => {
            task.abort();
            Ok(elapsed.max(1))
        }
        Ok(Err(e)) => {
            // если упал сам протокол — показать его ошибку
            if task.is_finished() {
                if let Ok(Err(pe)) = task.await {
                    return Err(pe);
                }
            } else {
                task.abort();
            }
            Err(e)
        }
        Err(_) => {
            task.abort();
            Err(io_err("таймаут"))
        }
    }
}
