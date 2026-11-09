//! Транспортный уровень: TCP → (TLS | REALITY) → (WebSocket | HTTPUpgrade | raw).

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
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;

use crate::common::{io_err, Address, BoxStream};
use crate::config::Profile;

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub async fn connect_tcp(addr: &Address) -> io::Result<TcpStream> {
    let fut = async {
        let sa = addr.resolve().await?;
        let s = TcpStream::connect(sa).await?;
        s.set_nodelay(true).ok();
        Ok::<_, io::Error>(s)
    };
    tokio::time::timeout(CONNECT_TIMEOUT, fut)
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
        "tcp" | "ws" | "httpupgrade" | "grpc" | "xhttp" => {}
        other => return Err(io_err(format!("транспорт «{other}» пока не поддерживается"))),
    }
    let tcp = connect_tcp(&server_addr(p)).await?;
    let secured: BoxStream = match p.security.as_str() {
        "tls" => {
            let default_alpn = match net {
                "ws" | "httpupgrade" => "http/1.1",
                "grpc" | "xhttp" => "h2",
                _ => "",
            };
            let alpn = if p.alpn.is_empty() { default_alpn } else { &p.alpn };
            Box::new(tls_connect(tcp, &sni_of(p), alpn, p.allow_insecure).await?)
        }
        "reality" => {
            let cfg = reality_config(p)?;
            let conn = tokio::time::timeout(CONNECT_TIMEOUT, reality::connect(tcp, &cfg))
                .await
                .map_err(|_| io_err("таймаут рукопожатия REALITY"))??;
            conn.into_stream()
        }
        _ => Box::new(tcp),
    };
    match net {
        "ws" => websocket(secured, p).await,
        "httpupgrade" => http_upgrade(secured, p).await,
        "grpc" => http2::grpc(secured, p).await,
        "xhttp" => http2::xhttp(secured, p).await,
        _ if p.header_type == "http" => http2::http_obfs(secured, p).await,
        _ => Ok(secured),
    }
}

// ───────────────────────── TLS (rustls) ─────────────────────────

#[derive(Debug)]
struct NoVerify(Arc<rustls::crypto::CryptoProvider>);

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

fn tls_config(alpn: &str, insecure: bool) -> Arc<rustls::ClientConfig> {
    static CACHE: OnceLock<Mutex<HashMap<(String, bool), Arc<rustls::ClientConfig>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let key = (alpn.to_string(), insecure);
    if let Some(c) = cache.lock().get(&key) {
        return c.clone();
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap();
    let mut cfg = if insecure {
        builder.dangerous().with_custom_certificate_verifier(Arc::new(NoVerify(provider))).with_no_client_auth()
    } else {
        let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    cfg.alpn_protocols =
        alpn.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).map(|s| s.as_bytes().to_vec()).collect();
    let cfg = Arc::new(cfg);
    cache.lock().insert(key, cfg.clone());
    cfg
}

pub async fn tls_connect<S>(stream: S, sni: &str, alpn: &str, insecure: bool) -> io::Result<tokio_rustls::client::TlsStream<S>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let connector = tokio_rustls::TlsConnector::from(tls_config(alpn, insecure));
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

async fn websocket(stream: BoxStream, p: &Profile) -> io::Result<BoxStream> {
    let host = ws_host(p);
    let url = format!("ws://{}{}", host, ws_path(p));
    let mut req = url.into_client_request().map_err(|e| io_err(format!("WS: {e}")))?;
    req.headers_mut().insert(
        "User-Agent",
        "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Mobile Safari/537.36"
            .parse()
            .unwrap(),
    );
    let (ws, _resp) = tokio::time::timeout(CONNECT_TIMEOUT, tokio_tungstenite::client_async(req, stream))
        .await
        .map_err(|_| io_err("таймаут WebSocket"))?
        .map_err(|e| io_err(format!("WebSocket: {e}")))?;
    let (mut sink, mut source) = ws.split();
    let (a, b) = tokio::io::duplex(128 * 1024);
    let (mut br, mut bw) = tokio::io::split(b);
    tokio::spawn(async move {
        let mut buf = vec![0u8; 16 * 1024];
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
    Ok(Box::new(a))
}

async fn http_upgrade(mut stream: BoxStream, p: &Profile) -> io::Result<BoxStream> {
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
        ws_path(p),
        ws_host(p)
    );
    stream.write_all(req.as_bytes()).await?;
    let mut resp = Vec::new();
    let mut b = [0u8; 1];
    while !resp.ends_with(b"\r\n\r\n") {
        if stream.read(&mut b).await? == 0 {
            return Err(io_err("HTTPUpgrade: соединение закрыто"));
        }
        resp.push(b[0]);
        if resp.len() > 8192 {
            return Err(io_err("HTTPUpgrade: слишком длинный ответ"));
        }
    }
    let line = String::from_utf8_lossy(&resp);
    if !line.starts_with("HTTP/1.1 101") {
        return Err(io_err(format!("HTTPUpgrade: {}", line.lines().next().unwrap_or(""))));
    }
    Ok(stream)
}
