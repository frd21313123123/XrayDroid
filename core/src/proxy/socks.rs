//! SOCKS5-клиент (только CONNECT).

use std::io;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::common::{io_err, Address, BoxStream};
use crate::config::Profile;
use crate::transport;

pub async fn tcp(p: &Profile, app: BoxStream, dest: &Address) -> io::Result<()> {
    let mut s = transport::connect_tcp(&transport::server_addr(p)).await?;
    let auth = !p.username.is_empty();
    s.write_all(if auth { &[5, 1, 2] } else { &[5, 1, 0] }).await?;
    let mut r = [0u8; 2];
    s.read_exact(&mut r).await?;
    match r[1] {
        0 => {}
        2 => {
            let mut a = vec![1u8, p.username.len() as u8];
            a.extend_from_slice(p.username.as_bytes());
            a.push(p.id_or_password.len() as u8);
            a.extend_from_slice(p.id_or_password.as_bytes());
            s.write_all(&a).await?;
            s.read_exact(&mut r).await?;
            if r[1] != 0 {
                return Err(io_err("SOCKS: неверный логин/пароль"));
            }
        }
        _ => return Err(io_err("SOCKS: метод аутентификации не принят")),
    }
    let mut req = vec![5, 1, 0];
    dest.write_socks(&mut req);
    s.write_all(&req).await?;
    let mut h = [0u8; 3];
    s.read_exact(&mut h).await?;
    if h[1] != 0 {
        return Err(io_err(format!("SOCKS: ошибка {}", h[1])));
    }
    Address::read_socks(&mut s).await?;
    crate::common::relay(app, s).await
}
