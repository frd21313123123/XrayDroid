//! Транспортный уровень: TCP → (TLS | REALITY) → (WebSocket | HTTPUpgrade | raw).

pub mod certs;
pub mod dialer;
pub mod http2;
pub mod reality;
pub mod secure;
pub mod tls13;

use std::collections::HashMap;
use std::io;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use parking_lot::Mutex;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;

use crate::common::{io_err, Address, BoxStream};
use crate::config::Profile;

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub async fn connect_tcp(addr: &Address) -> io::Result<TcpStream> {
    tokio::time::timeout(CONNECT_TIMEOUT, dialer::connect(addr))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, format!("таймаут подключения к {addr}")))?
}

pub fn server_addr(p: &Profile) -> Address {
    Address::new_domain(p.address.clone(), p.port)
}

pub fn sni_for(p: &Profile) -> String {
    sni_of(p)
}

fn sni_of(p: &Profile) -> String {
    if !p.sni.is_empty() {
        p.sni.clone()
    } else if !p.host.is_empty() && p.network != "tcp" {
        p.host.split(',').next().unwrap_or("").trim().to_string()
    } else {
        p.address.clone()
    }
}

pub fn reality_config(p: &Profile) -> io::Result<reality::RealityConfig> {
    reality::RealityConfig::new(&sni_of(p), &p.public_key, &p.short_id, &p.alpn)
}

pub fn network(p: &Profile) -> &str {
    match p.network.as_str() {
        "" | "raw" => "tcp",
        "websocket" => "ws",
        "splithttp" => "xhttp",
        "gun" => "grpc",
        n => n,
    }
}

/// Полная цепочка транспорта для профиля → поток, готовый для протокола.
pub async fn dial(p: &Profile) -> io::Result<BoxStream> {
    let net = network(p);
    match net {
        "tcp" | "ws" | "httpupgrade" => {}
        // HTTP/2-транспорты переиспользуют соединения: новый поток не требует нового рукопожатия
        "grpc" => return http2::grpc(p).await,
        "xhttp" => return http2::xhttp(p).await,
        other => return Err(io_err(format!("транспорт «{other}» пока не поддерживается"))),
    }
    let secured = dial_secured(p).await?;
    match net {
        "ws" => websocket(secured, p).await,
        "httpupgrade" => http_upgrade(secured, p).await,
        _ if p.header_type == "http" => http2::http_obfs(secured, p).await,
        _ => Ok(secured),
    }
}

/// TCP до сервера и слой безопасности профиля (TLS / REALITY / нет).
pub async fn dial_secured(p: &Profile) -> io::Result<BoxStream> {
    let net = network(p);
    match p.security.as_str() {
        "tls" => {
            let default_alpn = match net {
                "ws" | "httpupgrade" => "http/1.1",
                "grpc" | "xhttp" => "h2",
                _ => "",
            };
            let alpn = if p.alpn.is_empty() { default_alpn } else { &p.alpn };
            let tcp = dialer::connect_for_tls(&server_addr(p)).await?;
            tls_for_profile(tcp, p, alpn).await
        }
        "reality" => {
            let cfg = reality_config(p)?;
            let tcp = dialer::connect_for_tls(&server_addr(p)).await?;
            let conn = tokio::time::timeout(CONNECT_TIMEOUT, reality::connect_stream(tcp, &cfg))
                .await
                .map_err(|_| io_err("таймаут рукопожатия REALITY"))??;
            Ok(conn.into_stream())
        }
        _ => Ok(Box::new(connect_tcp(&server_addr(p)).await?)),
    }
}

// ───────────────────────── TLS ─────────────────────────

/// Нужен ли ClientHello как у браузера. Xray с `fp=chrome/firefox/…` использует uTLS,
/// и часть серверов/сетей пропускает только «браузерные» рукопожатия: стандартный
/// ClientHello rustls легко отличить и заблокировать.
fn browser_hello(fp: &str) -> bool {
    !matches!(fp.trim().to_ascii_lowercase().as_str(), "" | "none" | "golang")
}

/// Серверы, с которыми не получилось рукопожатие в стиле Chrome (только TLS 1.2,
/// HelloRetryRequest и т. п.): к ним сразу идём через rustls.
fn plain_tls_only() -> &'static Mutex<std::collections::HashSet<String>> {
    static SET: OnceLock<Mutex<std::collections::HashSet<String>>> = OnceLock::new();
    SET.get_or_init(Default::default)
}

/// TLS для профиля: ClientHello в стиле Chrome (как uTLS в Xray), при неудаче — rustls.
pub async fn tls_for_profile(tcp: BoxStream, p: &Profile, alpn: &str) -> io::Result<BoxStream> {
    let sni = sni_of(p);
    let key = format!("{}:{}|{}", p.address, p.port, sni);
    let policy = certs::CertPolicy::of(p);
    if browser_hello(&p.fingerprint) && !plain_tls_only().lock().contains(&key) {
        let protos: Vec<String> = alpn.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
        let hs = tls13::handshake(tcp, &sni, &protos, tls13::Mode::Verify(&policy));
        match tokio::time::timeout(CONNECT_TIMEOUT, hs).await {
            Ok(Ok(conn)) => return Ok(conn.into_stream()),
            Err(_) => return Err(io_err("таймаут TLS-рукопожатия")),
            Ok(Err(e)) => {
                log::info!("TLS {}: рукопожатие в стиле Chrome не удалось ({e}), пробую стандартное", p.address);
                let tcp = dialer::connect_for_tls(&server_addr(p)).await?;
                let s = tls_connect(tcp, &sni, alpn, &policy).await?;
                plain_tls_only().lock().insert(key);
                return Ok(Box::new(s));
            }
        }
    }
    Ok(Box::new(tls_connect(tcp, &sni, alpn, &policy).await?))
}

// ───────────────────────── TLS (rustls) ─────────────────────────

#[derive(Debug)]
pub struct NoVerify(Arc<rustls::crypto::CryptoProvider>);

/// Проверка сертификата отключена (allowInsecure).
pub type NoVerifyPub = NoVerify;

impl NoVerify {
    pub fn new(p: Arc<rustls::crypto::CryptoProvider>) -> Self {
        Self(p)
    }
}

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn tls_config(alpn: &str, policy: &certs::CertPolicy) -> Arc<rustls::ClientConfig> {
    static CACHE: OnceLock<Mutex<HashMap<(String, String), Arc<rustls::ClientConfig>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let key = (alpn.to_string(), policy.cache_key());
    if let Some(c) = cache.lock().get(&key) {
        return c.clone();
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap();
    let mut cfg = certs::client_config(builder, policy, provider);
    cfg.alpn_protocols =
        alpn.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).map(|s| s.as_bytes().to_vec()).collect();
    let cfg = Arc::new(cfg);
    cache.lock().insert(key, cfg.clone());
    cfg
}

pub async fn tls_connect<S>(
    stream: S,
    sni: &str,
    alpn: &str,
    policy: &certs::CertPolicy,
) -> io::Result<tokio_rustls::client::TlsStream<S>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let connector = tokio_rustls::TlsConnector::from(tls_config(alpn, policy));
    let name = ServerName::try_from(sni.to_string()).map_err(|_| io_err(format!("неверный SNI: {sni}")))?;
    tokio::time::timeout(CONNECT_TIMEOUT, connector.connect(name, stream))
        .await
        .map_err(|_| io_err("таймаут TLS-рукопожатия"))?
        .map_err(|e| io_err(format!("TLS: {e}")))
}

// ───────────────────────── WebSocket ─────────────────────────

fn ws_host(p: &Profile) -> String {
    if !p.host.is_empty() {
        p.host.split(',').next().unwrap_or("").trim().to_string()
    } else if !p.sni.is_empty() {
        p.sni.clone()
    } else {
        p.address.clone()
    }
}

fn ws_path(p: &Profile) -> String {
    if p.path.is_empty() {
        "/".into()
    } else if p.path.starts_with('/') {
        p.path.clone()
    } else {
        format!("/{}", p.path)
    }
}

/// Xray: `?ed=2048` в пути — не часть пути, а размер «ранних данных» (0-RTT):
/// первые байты уходят прямо в запросе рукопожатия.
pub fn split_early_data(path: &str) -> (String, usize) {
    let Some((base, query)) = path.split_once('?') else { return (path.to_string(), 0) };
    let mut ed = 0usize;
    let rest: Vec<&str> = query
        .split('&')
        .filter(|kv| match kv.strip_prefix("ed=") {
            Some(v) => {
                ed = v.parse().unwrap_or(0);
                false
            }
            None => !kv.is_empty(),
        })
        .collect();
    let path = if rest.is_empty() { base.to_string() } else { format!("{base}?{}", rest.join("&")) };
    (path, ed.min(8192))
}

const BROWSER_UA: &str =
    "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36";

async fn read_http_head(stream: &mut BoxStream, what: &str) -> io::Result<String> {
    let mut resp = Vec::new();
    let mut b = [0u8; 1];
    while !resp.ends_with(b"\r\n\r\n") {
        if stream.read(&mut b).await? == 0 {
            return Err(io_err(format!("{what}: соединение закрыто")));
        }
        resp.push(b[0]);
        if resp.len() > 16384 {
            return Err(io_err(format!("{what}: слишком длинный ответ")));
        }
    }
    Ok(String::from_utf8_lossy(&resp).into_owned())
}

type WsStream = tokio_tungstenite::WebSocketStream<BoxStream>;

/// Рукопожатие WebSocket. `early` — данные, которые едут в заголовке
/// `Sec-WebSocket-Protocol` (как в Xray и sing-box).
async fn ws_handshake(mut stream: BoxStream, host: &str, path: &str, early: Option<&[u8]>) -> io::Result<WsStream> {
    use base64::Engine;
    let mut key = [0u8; 16];
    crate::common::random_bytes(&mut key);
    let mut req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {}\r\nSec-WebSocket-Version: 13\r\nUser-Agent: {BROWSER_UA}\r\n",
        base64::engine::general_purpose::STANDARD.encode(key)
    );
    if let Some(e) = early.filter(|e| !e.is_empty()) {
        req.push_str(&format!("Sec-WebSocket-Protocol: {}\r\n", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(e)));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).await?;
    let head = read_http_head(&mut stream, "WebSocket").await?;
    let status = head.split_whitespace().nth(1).unwrap_or("");
    if status != "101" {
        return Err(io_err(format!("WebSocket: {}", head.lines().next().unwrap_or(""))));
    }
    Ok(tokio_tungstenite::WebSocketStream::from_raw_socket(stream, tokio_tungstenite::tungstenite::protocol::Role::Client, None).await)
}

fn ws_pumps(ws: WsStream, b: tokio::io::DuplexStream, first: Vec<u8>) {
    let (mut sink, mut source) = ws.split();
    let (mut br, mut bw) = tokio::io::split(b);
    tokio::spawn(async move {
        if !first.is_empty() && sink.send(Message::Binary(first.into())).await.is_err() {
            return;
        }
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            match br.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if sink.send(Message::Binary(buf[..n].to_vec().into())).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = sink.send(Message::Close(None)).await;
    });
    tokio::spawn(async move {
        while let Some(Ok(msg)) = source.next().await {
            let data = match msg {
                Message::Binary(d) => d.to_vec(),
                Message::Text(t) => t.as_bytes().to_vec(),
                Message::Close(_) => break,
                _ => continue,
            };
            if bw.write_all(&data).await.is_err() {
                break;
            }
        }
        let _ = bw.shutdown().await;
    });
}

async fn websocket(stream: BoxStream, p: &Profile) -> io::Result<BoxStream> {
    let host = ws_host(p);
    let (path, ed) = split_early_data(&ws_path(p));
    let (a, b) = tokio::io::duplex(128 * 1024);
    if ed == 0 {
        let ws = tokio::time::timeout(CONNECT_TIMEOUT, ws_handshake(stream, &host, &path, None))
            .await
            .map_err(|_| io_err("таймаут WebSocket"))??;
        ws_pumps(ws, b, Vec::new());
        return Ok(Box::new(a));
    }
    // ранние данные: рукопожатие откладывается до первой записи протокола
    let address = p.address.clone();
    tokio::spawn(async move {
        let mut b = b;
        let mut first = vec![0u8; 16 * 1024];
        let n = match b.read(&mut first).await {
            Ok(n) if n > 0 => n,
            _ => return,
        };
        first.truncate(n);
        let cut = n.min(ed);
        match tokio::time::timeout(CONNECT_TIMEOUT, ws_handshake(stream, &host, &path, Some(&first[..cut]))).await {
            Ok(Ok(ws)) => ws_pumps(ws, b, first.split_off(cut)),
            Ok(Err(e)) => log::warn!("{address}: {e}"),
            Err(_) => log::warn!("{address}: таймаут WebSocket"),
        }
    });
    Ok(Box::new(a))
}

async fn http_upgrade(mut stream: BoxStream, p: &Profile) -> io::Result<BoxStream> {
    let (path, _) = split_early_data(&ws_path(p));
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nUser-Agent: {BROWSER_UA}\r\n\r\n",
        ws_host(p)
    );
    stream.write_all(req.as_bytes()).await?;
    // Ответ ждём всегда: сервер Xray читает запрос через буфер и теряет данные,
    // пришедшие вместе с ним, поэтому отправка «вдогонку» (ed) ненадёжна.
    let head = read_http_head(&mut stream, "HTTPUpgrade").await?;
    if head.split_whitespace().nth(1) != Some("101") {
        return Err(io_err(format!("HTTPUpgrade: {}", head.lines().next().unwrap_or(""))));
    }
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn early_data_in_path() {
        assert_eq!(split_early_data("/ws?ed=2048"), ("/ws".to_string(), 2048));
        assert_eq!(split_early_data("/ws?a=b&ed=1024&c=d"), ("/ws?a=b&c=d".to_string(), 1024));
        assert_eq!(split_early_data("/ws"), ("/ws".to_string(), 0));
        assert_eq!(split_early_data("/ws?x=1"), ("/ws?x=1".to_string(), 0));
    }
}
