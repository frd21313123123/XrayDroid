//! Проверка сертификата сервера как в Xray-core:
//! - `allowInsecure` — без проверки (в Xray 26 убран, но старые ссылки его ещё используют);
//! - `pinnedPeerCertSha256` (`pcs` в ссылках) — SHA-256 сертификата. Совпал хеш конечного
//!   сертификата — проверка пройдена (так работают самоподписанные сертификаты); совпал хеш
//!   сертификата CA из цепочки — он становится единственным доверенным корнем;
//! - `verifyPeerCertByName` (`vcn`) — имя, по которому проверяется сертификат вместо SNI.

use std::sync::{Arc, OnceLock};

use base64::Engine;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, RootCertStore, SignatureScheme};
use sha2::{Digest, Sha256};

use crate::config::Profile;

/// Правила проверки сертификата для одного профиля.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CertPolicy {
    pub insecure: bool,
    pub pins: Vec<[u8; 32]>,
    pub names: Vec<String>,
}

impl CertPolicy {
    pub fn of(p: &Profile) -> Self {
        Self {
            insecure: p.allow_insecure,
            pins: parse_pins(&p.pinned_cert_sha256),
            names: p.verify_name.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(),
        }
    }

    /// Обычная проверка по корневым сертификатам и SNI.
    pub fn strict() -> Self {
        Self::default()
    }

    /// Нужна ли своя логика вместо стандартной проверки rustls.
    pub fn is_custom(&self) -> bool {
        !self.pins.is_empty() || !self.names.is_empty()
    }

    /// Ключ для кеша конфигураций TLS.
    pub fn cache_key(&self) -> String {
        let pins: Vec<String> = self.pins.iter().map(hex).collect();
        format!("{}|{}|{}", self.insecure, pins.join(","), self.names.join(","))
    }

    /// Проверяет цепочку сертификатов сервера (`chain[0]` — конечный сертификат).
    /// Подпись рукопожатия (CertificateVerify) проверяется отдельно.
    pub fn verify(&self, chain: &[CertificateDer<'_>], sni: &str) -> Result<(), String> {
        if self.insecure {
            return Ok(());
        }
        let ee = chain.first().ok_or("сервер не прислал сертификат")?;
        let inter = &chain[1..];
        let mut pinned_ca: Option<&CertificateDer<'_>> = None;
        if !self.pins.is_empty() {
            let leaf: [u8; 32] = Sha256::digest(ee.as_ref()).into();
            if self.pins.contains(&leaf) {
                return Ok(());
            }
            pinned_ca = inter.iter().find(|c| {
                let h: [u8; 32] = Sha256::digest(c.as_ref()).into();
                self.pins.contains(&h)
            });
            if pinned_ca.is_none() {
                return Err(format!(
                    "сертификат сервера не совпадает с закреплённым (pcs): SHA-256 сертификата {}",
                    hex(&Sha256::digest(ee.as_ref()).into())
                ));
            }
        }
        let verifier = match pinned_ca {
            Some(ca) => {
                let mut roots = RootCertStore::empty();
                roots.add(ca.clone().into_owned()).map_err(|e| format!("закреплённый CA (pcs): {e}"))?;
                build_verifier(roots)?
            }
            None => default_verifier(),
        };
        let names: Vec<&str> = if self.names.is_empty() { vec![sni] } else { self.names.iter().map(String::as_str).collect() };
        let mut last = String::new();
        for name in names {
            let Ok(sn) = ServerName::try_from(name.to_string()) else {
                last = format!("неверное имя для проверки сертификата: {name}");
                continue;
            };
            match verifier.verify_server_cert(ee, inter, &sn, &[], UnixTime::now()) {
                Ok(_) => return Ok(()),
                Err(e) => last = format!("сертификат не прошёл проверку: {e}"),
            }
        }
        Err(last)
    }
}

/// Разбирает `pcs`: SHA-256 в hex (можно с двоеточиями, как у OpenSSL), несколько — через запятую.
pub fn parse_pins(s: &str) -> Vec<[u8; 32]> {
    s.split(',')
        .filter_map(|v| {
            let v: String = v.chars().filter(|c| *c != ':' && !c.is_whitespace()).collect();
            if v.len() != 64 {
                return None;
            }
            let mut out = [0u8; 32];
            for (i, b) in out.iter_mut().enumerate() {
                *b = u8::from_str_radix(v.get(i * 2..i * 2 + 2)?, 16).ok()?;
            }
            Some(out)
        })
        .collect()
}

fn hex(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn build_verifier(roots: RootCertStore) -> Result<Arc<WebPkiServerVerifier>, String> {
    WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider()).build().map_err(|e| e.to_string())
}

/// Корневые сертификаты по умолчанию: webpki-roots и, при наличии, `XD_EXTRA_CA` (PEM).
pub fn default_roots() -> RootCertStore {
    let mut roots = RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
    if let Ok(path) = std::env::var("XD_EXTRA_CA") {
        if let Ok(pem) = std::fs::read_to_string(path) {
            for block in pem.split("-----BEGIN CERTIFICATE-----").skip(1) {
                let b64: String =
                    block.split("-----END").next().unwrap_or("").chars().filter(|c| !c.is_whitespace()).collect();
                if let Ok(der) = base64::engine::general_purpose::STANDARD.decode(b64) {
                    let _ = roots.add(CertificateDer::from(der));
                }
            }
        }
    }
    roots
}

fn default_verifier() -> Arc<WebPkiServerVerifier> {
    static V: OnceLock<Arc<WebPkiServerVerifier>> = OnceLock::new();
    V.get_or_init(|| build_verifier(default_roots()).expect("verifier")).clone()
}

/// Верификатор для rustls с правилами `pcs`/`vcn`.
#[derive(Debug)]
pub struct PolicyVerifier {
    policy: CertPolicy,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl PolicyVerifier {
    pub fn new(policy: CertPolicy, provider: Arc<rustls::crypto::CryptoProvider>) -> Self {
        Self { policy, provider }
    }
}

impl ServerCertVerifier for PolicyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let mut chain = Vec::with_capacity(intermediates.len() + 1);
        chain.push(end_entity.clone());
        chain.extend(intermediates.iter().cloned());
        let sni = match server_name {
            ServerName::DnsName(d) => d.as_ref().to_string(),
            ServerName::IpAddress(ip) => std::net::IpAddr::from(*ip).to_string(),
            _ => String::new(),
        };
        self.policy.verify(&chain, &sni).map(|_| ServerCertVerified::assertion()).map_err(rustls::Error::General)
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// Готовит rustls-конфигурацию с нужной проверкой сертификата.
pub fn client_config(
    builder: rustls::ConfigBuilder<rustls::ClientConfig, rustls::WantsVerifier>,
    policy: &CertPolicy,
    provider: Arc<rustls::crypto::CryptoProvider>,
) -> rustls::ClientConfig {
    if policy.insecure {
        builder.dangerous().with_custom_certificate_verifier(Arc::new(super::NoVerify::new(provider))).with_no_client_auth()
    } else if policy.is_custom() {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PolicyVerifier::new(policy.clone(), provider)))
            .with_no_client_auth()
    } else {
        builder.with_root_certificates(default_roots()).with_no_client_auth()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pins_openssl_and_plain() {
        let a = "01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF";
        let b = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let p = parse_pins(&format!("{a}, {b},bad"));
        assert_eq!(p.len(), 2);
        assert_eq!(p[0], p[1]);
        assert_eq!(p[0][0], 0x01);
        assert!(parse_pins("").is_empty());
    }
}
