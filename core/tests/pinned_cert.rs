//! Закрепление сертификата как в Xray: `pcs` (pinnedPeerCertSha256) и `vcn` (verifyPeerCertByName).
//! Сервер с самоподписанным сертификатом и SNI чужого сайта — так устроены gRPC-серверы
//! многих подписок после того, как Xray 26 убрал allowInsecure.

use std::sync::Arc;

use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use xd_core::config::Profile;

struct Certs {
    chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: Vec<u8>,
}

/// Самоподписанный сертификат на `name`.
fn self_signed(name: &str) -> Certs {
    let ck = rcgen::generate_simple_self_signed(vec![name.into()]).unwrap();
    Certs { chain: vec![ck.cert.der().clone()], key: ck.key_pair.serialize_der() }
}

/// Собственный CA → сертификат на `name`; цепочка: [leaf, ca].
fn with_ca(name: &str) -> Certs {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec![name.into()]).unwrap().signed_by(&leaf_key, &ca, &ca_key).unwrap();
    Certs { chain: vec![leaf.der().clone(), ca.der().clone()], key: leaf_key.serialize_der() }
}

fn sha256_hex(der: &[u8], colons: bool) -> String {
    let h = Sha256::digest(der);
    let parts: Vec<String> = h.iter().map(|b| format!("{b:02X}")).collect();
    parts.join(if colons { ":" } else { "" })
}

/// TLS-эхо (HTTP/1.1 ALPN не нужен — транспорт raw TCP).
async fn serve(c: &Certs) -> u16 {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(c.key.clone().into());
    let cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(c.chain.clone(), key)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = l.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else { return };
                let mut buf = [0u8; 4096];
                while let Ok(n) = tls.read(&mut buf).await {
                    if n == 0 || tls.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                    let _ = tls.flush().await;
                }
            });
        }
    });
    port
}

fn profile(port: u16, fp: &str, sni: &str, pcs: &str, vcn: &str) -> Profile {
    Profile {
        address: "127.0.0.1".into(),
        port,
        network: "tcp".into(),
        security: "tls".into(),
        sni: sni.into(),
        fingerprint: fp.into(),
        pinned_cert_sha256: pcs.into(),
        verify_name: vcn.into(),
        ..Default::default()
    }
}

async fn echo(p: &Profile) -> std::io::Result<()> {
    let mut s = xd_core::transport::dial(p).await?;
    s.write_all(b"ping-pong").await?;
    let mut got = [0u8; 9];
    tokio::time::timeout(std::time::Duration::from_secs(5), s.read_exact(&mut got)).await??;
    assert_eq!(&got, b"ping-pong");
    Ok(())
}

#[tokio::test]
async fn pinned_leaf_with_foreign_sni() {
    // сертификат на один домен, SNI — другой (как foreign.example в подписке), pcs — хеш сертификата
    let c = self_signed("my-proxy.local");
    let port = serve(&c).await;
    let pin = sha256_hex(&c.chain[0], true);
    for fp in ["chrome", "edge", "qq", ""] {
        echo(&profile(port, fp, "foreign.example", &pin, "")).await.unwrap_or_else(|e| panic!("fp={fp}: {e}"));
    }
    // hex без двоеточий и несколько значений через запятую
    let plain = format!("{},{}", "00".repeat(32), sha256_hex(&c.chain[0], false).to_lowercase());
    echo(&profile(port, "chrome", "foreign.example", &plain, "")).await.unwrap();
}

#[tokio::test]
async fn self_signed_without_pin_is_rejected() {
    let c = self_signed("my-proxy.local");
    let port = serve(&c).await;
    for fp in ["chrome", ""] {
        assert!(echo(&profile(port, fp, "foreign.example", "", "")).await.is_err(), "fp={fp}");
    }
}

#[tokio::test]
async fn wrong_pin_is_rejected() {
    let c = self_signed("my-proxy.local");
    let port = serve(&c).await;
    let wrong = "AB".repeat(32);
    for fp in ["chrome", ""] {
        assert!(echo(&profile(port, fp, "foreign.example", &wrong, "")).await.is_err(), "fp={fp}");
    }
}

#[tokio::test]
async fn pinned_ca_checks_name() {
    let c = with_ca("my-proxy.local");
    let port = serve(&c).await;
    let ca_pin = sha256_hex(&c.chain[1], true);
    for fp in ["chrome", ""] {
        // CA закреплён, имя совпадает с SNI
        echo(&profile(port, fp, "my-proxy.local", &ca_pin, "")).await.unwrap_or_else(|e| panic!("fp={fp}: {e}"));
        // CA закреплён, но SNI чужой — без vcn нельзя
        assert!(echo(&profile(port, fp, "foreign.example", &ca_pin, "")).await.is_err(), "fp={fp}");
        // CA закреплён, SNI чужой, проверка по имени из vcn
        echo(&profile(port, fp, "foreign.example", &ca_pin, "other.local,my-proxy.local")).await.unwrap_or_else(|e| panic!("fp={fp}: {e}"));
    }
}

#[test]
fn links_keep_pcs_and_vcn() {
    let link = "vless://00000000-0000-4000-8000-000000000001@203.0.113.10:443?encryption=none&type=grpc&serviceName=example.v1.Service&mode=gun&security=tls&sni=foreign.example&fp=edge&pcs=0F%3A0F%3A0F%3A0F%3A0F%3A0F%3A0F%3A0F%3A0F%3A0F%3A0F%3A0F%3A0F%3A0F%3A0F%3A0F%3A0F%3A0F%3A0F%3A0F%3A0F%3A0F%3A0F%3A0F%3A0F%3A0F%3A0F%3A0F%3A0F%3A0F%3A0F%3A0F&vcn=example.com#test";
    let p = xd_core::links::parse_link(link).unwrap();
    assert_eq!(p.pinned_cert_sha256, "0F:0F:0F:0F:0F:0F:0F:0F:0F:0F:0F:0F:0F:0F:0F:0F:0F:0F:0F:0F:0F:0F:0F:0F:0F:0F:0F:0F:0F:0F:0F:0F");
    assert_eq!(p.verify_name, "example.com");
    assert_eq!(xd_core::transport::certs::parse_pins(&p.pinned_cert_sha256).len(), 1);
    let back = xd_core::links::parse_link(&xd_core::links::to_link(&p)).unwrap();
    assert_eq!(back.pinned_cert_sha256, p.pinned_cert_sha256);
    assert_eq!(back.verify_name, p.verify_name);

    // VMess (JSON) с полями pcs/vcn, как в ключе пользователя
    let vm = xd_core::links::parse_link(&xd_core::links::to_link(&Profile {
        protocol: xd_core::config::Protocol::Vmess,
        address: "1.2.3.4".into(),
        port: 443,
        id_or_password: "00000000-0000-4000-8000-000000000002".into(),
        security: "tls".into(),
        pinned_cert_sha256: "ab".repeat(32),
        ..Default::default()
    }))
    .unwrap();
    assert_eq!(vm.pinned_cert_sha256, "ab".repeat(32));
}

#[tokio::test]
async fn chrome_hello_itself_accepts_pin() {
    // без отката на rustls: собственный TLS 1.3-клиент (как для Vision и fp=chrome)
    use xd_core::transport::{certs::CertPolicy, tls13};
    let c = self_signed("my-proxy.local");
    let port = serve(&c).await;
    let hs = |policy: CertPolicy| async move {
        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        tls13::handshake(Box::new(tcp), "foreign.example", &[], tls13::Mode::Verify(&policy)).await.map(|_| ())
    };
    let pinned = CertPolicy { pins: xd_core::transport::certs::parse_pins(&sha256_hex(&c.chain[0], true)), ..Default::default() };
    hs(pinned).await.unwrap();
    assert!(hs(CertPolicy::strict()).await.is_err());
}
