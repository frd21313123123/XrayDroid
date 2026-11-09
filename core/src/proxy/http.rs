//! HTTP(S)-прокси: метод CONNECT, опционально Basic-аутентификация и TLS до прокси.

use std::io;

use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::common::{io_err, Address, BoxStream, Host};
use crate::config::Profile;
use crate::transport;

pub async fn tcp(p: &Profile, app: BoxStream, dest: &Address) -> io::Result<()> {
    let mut s = transport::dial(p).await?;
    let target = match &dest.host {
        Host::Domain(d) => format!("{d}:{}", dest.port),
        _ => dest.to_string(),
    };
    let mut req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Connection: Keep-Alive\r\n");
    if !p.username.is_empty() || !p.id_or_password.is_empty() {
        let cred = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", p.username, p.id_or_password));
        req.push_str(&format!("Proxy-Authorization: Basic {cred}\r\n"));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).await?;
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if s.read(&mut b).await? == 0 {
            return Err(io_err("HTTP-прокси закрыл соединение"));
        }
        head.push(b[0]);
        if head.len() > 16384 {
            return Err(io_err("HTTP-прокси: слишком длинный ответ"));
        }
    }
    let line = String::from_utf8_lossy(&head);
    let status = line.split_whitespace().nth(1).unwrap_or("");
    if status != "200" {
        return Err(io_err(format!("HTTP-прокси: {}", line.lines().next().unwrap_or(""))));
    }
    crate::common::relay(app, s).await
}
