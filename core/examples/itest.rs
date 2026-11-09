//! Утилита для интеграционных тестов на десктопе:
//!   itest socks <link> <port>    — SOCKS5-вход через сервер из ссылки
//!   itest udp <link> <host:port> — отправить UDP-пакет и дождаться ответа
//!   itest delay <link> <url>     — тест задержки
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use xd_core::common::Address;
use xd_core::proxy::Outbound;

fn main() {
    xd_core::logbuf::init(None, true);
    xd_core::logbuf::set_sink(|l| eprintln!("{l}"));
    let a: Vec<String> = std::env::args().collect();
    let p = xd_core::links::parse_link(&a[2]).expect("bad link");
    match a[1].as_str() {
        "socks" => {
            let mut cfg = xd_core::AppConfig::default();
            xd_core::route::presets::apply_preset(&mut cfg.routing, "global");
            cfg.settings.socks_port = a[3].parse().unwrap();
            cfg.selected = p.id.clone();
            cfg.profiles.push(p);
            xd_core::engine::start(&cfg, std::path::Path::new("."), None).unwrap();
            loop {
                std::thread::sleep(std::time::Duration::from_secs(3600));
            }
        }
        "udp" => {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let (mut c, s) = tokio::io::duplex(65536);
                let ob = Outbound::Proxy(Arc::new(p));
                let (h, port) = a[3].rsplit_once(':').unwrap();
                let dest = Address::new_domain(h, port.parse().unwrap());
                let t = tokio::spawn(async move { ob.handle_udp(Box::new(s), &dest).await });
                for i in 0..3 {
                    if c.write_all(format!("ping{i}").as_bytes()).await.is_err() { println!("task: {:?}", t.await); return; }
                    let mut b = [0u8; 100];
                    let n = tokio::time::timeout(std::time::Duration::from_secs(5), c.read(&mut b)).await;
                    match n {
                        Ok(Ok(n)) => println!("UDP reply: {}", String::from_utf8_lossy(&b[..n])),
                        other => {
                            println!("UDP FAIL: {other:?}");
                            if t.is_finished() {
                                println!("task: {:?}", t.await);
                            }
                            return;
                        }
                    }
                }
            });
        }
        "delay" => {
            let r = xd_core::engine::shared_runtime().block_on(xd_core::engine::delay_test(&p, &a[3]));
            println!("delay: {r:?}");
        }
        _ => panic!("mode"),
    }
}
