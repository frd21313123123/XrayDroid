//! VLESS (без шифрования, flow="" или xtls-rprx-vision).

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::common::{io_err, Address, BoxStream};
use crate::config::Profile;
use crate::transport;

pub const FLOW_VISION: &str = "xtls-rprx-vision";

pub fn parse_uuid(s: &str) -> io::Result<[u8; 16]> {
    let s = s.trim();
    if let Ok(u) = uuid::Uuid::parse_str(s) {
        return Ok(*u.as_bytes());
    }
    // Xray допускает произвольную строку: UUIDv5 от неё (namespace = нулевой UUID)
    if !s.is_empty() && s.len() <= 30 {
        use sha1::{Digest, Sha1};
        let mut h = Sha1::new();
        h.update([0u8; 16]);
        h.update(s.as_bytes());
        let d = h.finalize();
        let mut b = [0u8; 16];
        b.copy_from_slice(&d[..16]);
        b[6] = (b[6] & 0x0f) | 0x50;
        b[8] = (b[8] & 0x3f) | 0x80;
        return Ok(b);
    }
    Err(io_err("неверный UUID"))
}

pub const CMD_TCP: u8 = 1;
pub const CMD_UDP: u8 = 2;

pub fn request_header(uuid: &[u8; 16], cmd: u8, dest: &Address, flow: &str) -> Vec<u8> {
    let mut h = Vec::with_capacity(64);
    h.push(0); // version
    h.extend_from_slice(uuid);
    if flow.is_empty() {
        h.push(0);
    } else {
        // protobuf Addons { string Flow = 1; }
        h.push((flow.len() + 2) as u8);
        h.push(0x0a);
        h.push(flow.len() as u8);
        h.extend_from_slice(flow.as_bytes());
    }
    h.push(cmd);
    dest.write_vless(&mut h);
    h
}

/// Поток, отбрасывающий заголовок ответа VLESS: version(1) + addons_len(1) + addons.
pub struct RespStripped<S> {
    inner: S,
    need: usize, // сколько байт заголовка ещё пропустить; usize::MAX — ждём первые 2 байта
    head: Vec<u8>,
    pending: Vec<u8>,
}

impl<S> RespStripped<S> {
    pub fn new(inner: S) -> Self {
        Self { inner, need: usize::MAX, head: Vec::new(), pending: Vec::new() }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for RespStripped<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if !this.pending.is_empty() {
            let n = this.pending.len().min(buf.remaining());
            buf.put_slice(&this.pending[..n]);
            this.pending.drain(..n);
            return Poll::Ready(Ok(()));
        }
        if this.need == 0 {
            return Pin::new(&mut this.inner).poll_read(cx, buf);
        }
        loop {
            let mut tmp = [0u8; 16 * 1024];
            let mut rb = ReadBuf::new(&mut tmp);
            ready!(Pin::new(&mut this.inner).poll_read(cx, &mut rb))?;
            let data = rb.filled();
            if data.is_empty() {
                return Poll::Ready(Ok(()));
            }
            let mut i = 0;
            while i < data.len() && this.need != 0 {
                if this.need == usize::MAX {
                    this.head.push(data[i]);
                    i += 1;
                    if this.head.len() == 2 {
                        if this.head[0] != 0 {
                            return Poll::Ready(Err(io_err("VLESS: неверная версия ответа")));
                        }
                        this.need = this.head[1] as usize;
                    }
                } else {
                    let k = this.need.min(data.len() - i);
                    i += k;
                    this.need -= k;
                }
            }
            if i < data.len() {
                let rest = &data[i..];
                let n = rest.len().min(buf.remaining());
                buf.put_slice(&rest[..n]);
                this.pending.extend_from_slice(&rest[n..]);
                return Poll::Ready(Ok(()));
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for RespStripped<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Читает первые данные приложения (до `wait`), чтобы отправить их вместе с заголовком.
pub async fn first_payload<R: AsyncRead + Unpin>(app: &mut R, wait_ms: u64) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; 16 * 1024];
    match tokio::time::timeout(std::time::Duration::from_millis(wait_ms), app.read(&mut buf)).await {
        Ok(Ok(n)) => {
            buf.truncate(n);
            Ok(buf)
        }
        Ok(Err(e)) => Err(e),
        Err(_) => Ok(Vec::new()),
    }
}

pub async fn tcp(p: &Profile, mut app: BoxStream, dest: &Address) -> io::Result<()> {
    let uuid = parse_uuid(&p.id_or_password)?;
    if p.flow.starts_with(FLOW_VISION) {
        if p.security == "reality" && transport::network(p) == "tcp" {
            return super::vision::run(p, uuid, app, dest).await;
        }
        if p.security != "reality" {
            return Err(io_err("flow xtls-rprx-vision поддерживается только вместе с REALITY"));
        }
    }
    let mut server = transport::dial(p).await?;
    let mut hdr = request_header(&uuid, CMD_TCP, dest, "");
    hdr.extend_from_slice(&first_payload(&mut app, 50).await?);
    server.write_all(&hdr).await?;
    crate::common::relay(app, RespStripped::new(server)).await
}

pub async fn udp(p: &Profile, app: BoxStream, dest: &Address) -> io::Result<()> {
    let uuid = parse_uuid(&p.id_or_password)?;
    // UDP идёт без flow (Xray принимает UDP без flow даже для vision-пользователей)
    let mut server = transport::dial(p).await?;
    server.write_all(&request_header(&uuid, CMD_UDP, dest, "")).await?;
    let server = RespStripped::new(server);
    super::udp_over_stream(app, server, super::UdpFraming::LenPrefixed).await
}
