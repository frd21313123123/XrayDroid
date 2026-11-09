//! gRPC поверх TLS против локального сервера (rustls + h2): ClientHello в стиле Chrome,
//! путь gRPC как в Xray и откат на rustls для сервера только с TLS 1.2.

use std::sync::Arc;

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use xd_core::config::Profile;

fn server_config(tls12_only: bool) -> Arc<rustls::ServerConfig> {
    let ck = rcgen::generate_simple_self_signed(vec!["test.local".into()]).unwrap();
    let cert = rustls::pki_types::CertificateDer::from(ck.cert.der().to_vec());
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(ck.key_pair.serialize_der().into());
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let versions: &[&rustls::SupportedProtocolVersion] =
        if tls12_only { &[&rustls::version::TLS12] } else { &[&rustls::version::TLS13, &rustls::version::TLS12] };
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    Arc::new(cfg)
}

/// gRPC-эхо: принимает только путь `expect_path`, возвращает тело как есть.
async fn serve(tls12_only: bool, expect_path: &'static str) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let acceptor = tokio_rustls::TlsAcceptor::from(server_config(tls12_only));
    tokio::spawn(async move {
        loop {
            let (tcp, _) = l.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else { return };
                let mut conn = h2::server::handshake(tls).await.unwrap();
                while let Some(Ok((req, mut resp))) = conn.accept().await {
                    let ok = req.uri().path() == expect_path;
                    tokio::spawn(async move {
                        let status = if ok { 200 } else { 404 };
                        let r = http::Response::builder().status(status).body(()).unwrap();
                        let mut tx = resp.send_response(r, !ok).unwrap();
                        if !ok {
                            return;
                        }
                        let mut body = req.into_body();
                        while let Some(Ok(chunk)) = body.data().await {
                            let _ = body.flow_control().release_capacity(chunk.len());
                            tx.send_data(Bytes::from(chunk.to_vec()), false).unwrap();
                        }
                    });
                }
            });
        }
    });
    port
}

fn profile(port: u16, fp: &str) -> Profile {
    Profile {
        address: "127.0.0.1".into(),
        port,
        network: "grpc".into(),
        security: "tls".into(),
        sni: "test.local".into(),
        path: "my-svc.v2".into(),
        fingerprint: fp.into(),
        allow_insecure: true,
        ..Default::default()
    }
}

async fn echo(p: &Profile) {
    let mut s = xd_core::transport::dial(p).await.expect("dial");
    let msg = vec![0x5au8; 70_000];
    s.write_all(&msg).await.unwrap();
    let mut got = vec![0u8; msg.len()];
    tokio::time::timeout(std::time::Duration::from_secs(5), s.read_exact(&mut got)).await.expect("timeout").unwrap();
    assert_eq!(got, msg);
}

#[tokio::test]
async fn grpc_over_chrome_tls() {
    let port = serve(false, "/my-svc.v2/Tun").await;
    echo(&profile(port, "chrome")).await;
}

#[tokio::test]
async fn grpc_over_rustls() {
    let port = serve(false, "/my-svc.v2/Tun").await;
    echo(&profile(port, "")).await;
}

#[tokio::test]
async fn chrome_falls_back_for_tls12_server() {
    let port = serve(true, "/my-svc.v2/Tun").await;
    echo(&profile(port, "chrome")).await;
    // второй раз — сразу через rustls (запомнено)
    echo(&profile(port, "chrome")).await;
}
