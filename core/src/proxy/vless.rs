//! VLESS (без шифрования, flow="" или xtls-rprx-vision).

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::common::{io_err, Address, BoxStream};
use crate::config::Profile;
use crate::transport::secure::SecureConn;
use crate::transport::{self, reality, tls13};

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
pub const CMD_MUX: u8 = 3;

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
    if cmd != CMD_MUX {
        dest.write_vless(&mut h);
    }
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

/// Защищённый слой, поверх которого работает Vision.
async fn vision_conn(p: &Profile, enc: &Option<super::vless_enc::EncConfig>) -> io::Result<SecureConn> {
    let net = transport::network(p);
    if let Some(e) = enc {
        let base = transport::dial(p).await?;
        return tokio::time::timeout(transport::CONNECT_TIMEOUT, super::vless_enc::handshake(base, e))
            .await
            .map_err(|_| io_err("таймаут рукопожатия VLESS Encryption"))?;
    }
    if net != "tcp" {
        return Err(io_err("flow xtls-rprx-vision работает только с транспортом TCP (или с VLESS Encryption)"));
    }
    let tcp = transport::dialer::connect_for_tls(&transport::server_addr(p)).await?;
    let fut = async {
        match p.security.as_str() {
            "reality" => reality::connect_stream(tcp, &transport::reality_config(p)?).await,
            "tls" => {
                let sni = transport::sni_for(p);
                let alpn: Vec<String> =
                    p.alpn.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
                let alpn = if alpn.is_empty() { vec!["h2".into(), "http/1.1".into()] } else { alpn };
                let policy = transport::certs::CertPolicy::of(p);
                tls13::handshake(tcp, &sni, &alpn, tls13::Mode::Verify(&policy)).await
            }
            _ => Err(io_err("flow xtls-rprx-vision требует TLS, REALITY или VLESS Encryption")),
        }
    };
    tokio::time::timeout(transport::CONNECT_TIMEOUT, fut).await.map_err(|_| io_err("таймаут TLS-рукопожатия"))?
}

pub async fn tcp(p: &Profile, mut app: BoxStream, dest: &Address) -> io::Result<()> {
    let uuid = parse_uuid(&p.id_or_password)?;
    let enc = super::vless_enc::parse(&p.method)?;
    if p.flow.starts_with(FLOW_VISION) {
        let conn = vision_conn(p, &enc).await?;
        return super::vision::run(conn, uuid, app, request_header(&uuid, CMD_TCP, dest, FLOW_VISION)).await;
    }
    let mut server = transport::dial(p).await?;
    if let Some(e) = &enc {
        server = super::vless_enc::handshake(server, e).await?.into_stream();
    }
    let mut hdr = request_header(&uuid, CMD_TCP, dest, "");
    hdr.extend_from_slice(&first_payload(&mut app, 50).await?);
    server.write_all(&hdr).await?;
    crate::common::relay(app, RespStripped::new(server)).await
}

pub async fn udp(p: &Profile, app: BoxStream, dest: &Address) -> io::Result<()> {
    let uuid = parse_uuid(&p.id_or_password)?;
    let enc = super::vless_enc::parse(&p.method)?;
    if p.flow.starts_with(FLOW_VISION) {
        // как в Xray: UDP через Vision идёт по XUDP (Mux.Cool), UDP/443 отклоняется
        if dest.port == 443 && !p.flow.ends_with("-udp443") {
            return Err(io_err("XTLS отклоняет UDP/443 (QUIC) — браузер перейдёт на TCP"));
        }
        let conn = vision_conn(p, &enc).await?;
        return xudp(conn, uuid, app, dest).await;
    }
    let mut server = transport::dial(p).await?;
    if let Some(e) = &enc {
        server = super::vless_enc::handshake(server, e).await?.into_stream();
    }
    server.write_all(&request_header(&uuid, CMD_UDP, dest, "")).await?;
    let server = RespStripped::new(server);
    super::udp_over_stream(app, server, super::UdpFraming::LenPrefixed).await
}

/// XUDP: UDP-пакеты кадрами Mux.Cool (сессия 0) внутри Vision.
async fn xudp(conn: SecureConn, uuid: [u8; 16], app: BoxStream, dest: &Address) -> io::Result<()> {
    let (mux_a, mux_b) = tokio::io::duplex(256 * 1024);
    let header = request_header(&uuid, CMD_MUX, dest, FLOW_VISION);
    let vision = tokio::spawn(super::vision::run(conn, uuid, Box::new(mux_b), header));
    let (mut ar, mut aw) = tokio::io::split(app);
    let (mut mr, mut mw) = tokio::io::split(mux_a);
    let d = dest.clone();
    let up = async move {
        let mut buf = vec![0u8; 65536];
        let mut first = true;
        loop {
            let n = match tokio::time::timeout(super::UDP_IDLE, ar.read(&mut buf)).await {
                Ok(Ok(0)) | Err(_) => break,
                Ok(Ok(n)) => n,
                Ok(Err(e)) => return Err(e),
            };
            if n + 666 > 8192 {
                continue;
            }
            let mut meta = vec![0u8, 0];
            meta.push(if first { 1 } else { 2 });
            meta.push(1);
            meta.push(2);
            d.write_vless(&mut meta);
            if first {
                meta.extend_from_slice(&[0u8; 8]);
                first = false;
            }
            let mut f = Vec::with_capacity(meta.len() + n + 6);
            f.extend_from_slice(&(meta.len() as u16).to_be_bytes());
            f.extend_from_slice(&meta);
            f.extend_from_slice(&(n as u16).to_be_bytes());
            f.extend_from_slice(&buf[..n]);
            mw.write_all(&f).await?;
        }
        let _ = mw.shutdown().await;
        Ok::<_, io::Error>(())
    };
    let down = async move {
        // заголовок ответа VLESS уже снят внутри Vision
        let resp = &mut mr;
        loop {
            let l = match tokio::time::timeout(super::UDP_IDLE, resp.read_u16()).await {
                Ok(Ok(l)) => l as usize,
                _ => break,
            };
            if l < 4 {
                break;
            }
            let mut meta = vec![0u8; l];
            resp.read_exact(&mut meta).await?;
            let status = meta[2];
            let has_data = meta[3] & 1 == 1;
            let data = if has_data {
                let dl = resp.read_u16().await? as usize;
                let mut v = vec![0u8; dl];
                resp.read_exact(&mut v).await?;
                Some(v)
            } else {
                None
            };
            match status {
                1 | 2 => {
                    if let Some(v) = data {
                        aw.write_all(&v).await?;
                    }
                }
                4 => {}
                _ => break,
            }
        }
        Ok::<_, io::Error>(())
    };
    let r = tokio::select! {
        r = up => r,
        r = down => r,
    };
    vision.abort();
    r
}
