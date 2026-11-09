//! XrayDroid core: протоколы VLESS (REALITY, Vision), VMess, Trojan, Shadowsocks, SOCKS;
//! транспорты TCP/TLS/WebSocket/HTTPUpgrade; TUN-стек, FakeDNS и маршрутизация.

pub mod common;
pub mod config;
pub mod engine;
pub mod links;
pub mod logbuf;
pub mod proxy;
pub mod route;
pub mod subscription;
pub mod transport;
pub mod tun;

pub use config::*;
