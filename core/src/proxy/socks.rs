//! SOCKS5-клиент: CONNECT и UDP ASSOCIATE.

use std::io;
use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::common::{io_err, Address, BoxStream};
use crate::config::Profile;
use crate::transport;

/// Подключение к прокси, аутентификация и команда; возвращает адрес из ответа.
async fn request(p: &Profile, cmd: u8, dest: &Address) -> io::Result<(TcpStream, Address)> {
    let mut s = transport::connect_tcp(&transport::server_addr(p)).await?;
    let auth = !p.username.is_empty();
    s.write_all(if auth { &[5, 2, 0, 2] } else { &[5, 1, 0] }).await?;
    let mut r = [0u8; 2];
    s.read_exact(&mut r).await?;
    match r[1] {
        0 => {}
        2 => {
            let mut a = vec![1u8, p.username.len().min(255) as u8];
            a.extend_from_slice(&p.username.as_bytes()[..p.username.len().min(255)]);
            a.push(p.id_or_password.len().min(255) as u8);
            a.extend_from_slice(&p.id_or_password.as_bytes()[..p.id_or_password.len().min(255)]);
            s.write_all(&a).await?;
            s.read_exact(&mut r).await?;
            if r[1] != 0 {
                return Err(io_err("SOCKS: неверный логин/пароль"));
            }
        }
        _ => return Err(io_err("SOCKS: метод аутентификации не принят")),
    }
    let mut req = vec![5, cmd, 0];
    dest.write_socks(&mut req);
    s.write_all(&req).await?;
    let mut h = [0u8; 3];
    s.read_exact(&mut h).await?;
    if h[1] != 0 {
        let why = match h[1] {
            2 => "соединение запрещено правилами",
            3 => "сеть недоступна",
            4 => "узел недоступен",
            5 => "в соединении отказано",
            7 => "команда не поддерживается",
            _ => "ошибка сервера",
        };
        return Err(io_err(format!("SOCKS: {why} (код {})", h[1])));
    }
    let bound = Address::read_socks(&mut s).await?;
    Ok((s, bound))
}

pub async fn tcp(p: &Profile, app: BoxStream, dest: &Address) -> io::Result<()> {
    let (s, _) = request(p, 1, dest).await?;
    crate::common::relay(app, s).await
}

pub async fn udp(p: &Profile, mut app: BoxStream, dest: &Address) -> io::Result<()> {
    let any = Address::from_socket(SocketAddr::from(([0, 0, 0, 0], 0)));
    let (mut ctrl, bound) = request(p, 3, &any).await?;
    // сервер часто отвечает 0.0.0.0 — тогда ретранслятор на том же адресе, что и сам прокси
    let peer = ctrl.peer_addr()?;
    let relay = match bound.ip() {
        Some(ip) if !ip.is_unspecified() => SocketAddr::new(ip, bound.port),
        Some(_) => SocketAddr::new(peer.ip(), bound.port),
        None => bound.resolve().await?,
    };
    let bind: SocketAddr = if relay.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }.parse().unwrap();
    let sock = tokio::net::UdpSocket::bind(bind).await?;
    sock.connect(relay).await?;
    let mut head = vec![0u8, 0, 0];
    dest.write_socks(&mut head);
    let mut a = vec![0u8; 65536];
    let mut b = vec![0u8; 65536];
    let mut c = [0u8; 1];
    loop {
        tokio::select! {
            r = app.read(&mut a) => {
                let n = r?;
                if n == 0 { break; }
                let mut pkt = Vec::with_capacity(head.len() + n);
                pkt.extend_from_slice(&head);
                pkt.extend_from_slice(&a[..n]);
                sock.send(&pkt).await?;
            }
            r = sock.recv(&mut b) => {
                let n = r?;
                // RSV(2) FRAG(1) ATYP+адрес+порт, затем данные; фрагменты не поддерживаются
                if n < 4 || b[2] != 0 { continue; }
                let Some((_, used)) = Address::parse_socks(&b[3..n]) else { continue };
                app.write_all(&b[3 + used..n]).await?;
            }
            // управляющее соединение живёт, пока жива ассоциация
            r = ctrl.read(&mut c) => {
                if matches!(r, Ok(0) | Err(_)) { break; }
            }
            _ = tokio::time::sleep(super::UDP_IDLE) => break,
        }
    }
    Ok(())
}
