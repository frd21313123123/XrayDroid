//! Модель конфигурации приложения: профили серверов, подписки, маршрутизация, настройки.

use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    #[default]
    Vless,
    Vmess,
    Trojan,
    Shadowsocks,
    Socks,
    Hysteria2,
    Tuic,
    #[serde(rename = "anytls")]
    AnyTls,
    Http,
}

impl Protocol {
    pub fn name(&self) -> &'static str {
        match self {
            Protocol::Vless => "VLESS",
            Protocol::Vmess => "VMess",
            Protocol::Trojan => "Trojan",
            Protocol::Shadowsocks => "Shadowsocks",
            Protocol::Socks => "SOCKS",
            Protocol::Hysteria2 => "Hysteria2",
            Protocol::Tuic => "TUIC",
            Protocol::AnyTls => "AnyTLS",
            Protocol::Http => "HTTP",
        }
    }
    pub fn all() -> [Protocol; 9] {
        [
            Protocol::Vless,
            Protocol::Vmess,
            Protocol::Trojan,
            Protocol::Shadowsocks,
            Protocol::Socks,
            Protocol::Hysteria2,
            Protocol::Tuic,
            Protocol::AnyTls,
            Protocol::Http,
        ]
    }
    /// Протоколы с выбором транспорта (ws, grpc, xhttp…)
    pub fn has_transport(&self) -> bool {
        matches!(self, Protocol::Vless | Protocol::Vmess | Protocol::Trojan)
    }
}

/// Профиль сервера. Плоская структура — удобно редактировать в UI и
/// конвертировать из/в ссылки.
#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq)]
#[serde(default)]
pub struct Profile {
    pub id: String,
    pub remarks: String,
    /// id подписки, из которой пришёл профиль ("" — добавлен вручную)
    pub sub_id: String,
    pub protocol: Protocol,
    pub address: String,
    pub port: u16,
    /// UUID (VLESS/VMess) или пароль (Trojan/SS/SOCKS)
    pub id_or_password: String,
    /// Имя пользователя для SOCKS
    pub username: String,
    /// Метод шифрования: SS cipher / VMess security / VLESS encryption
    pub method: String,
    /// VLESS flow (xtls-rprx-vision)
    pub flow: String,
    /// Транспорт: tcp | ws | httpupgrade | grpc | xhttp
    pub network: String,
    pub header_type: String,
    pub host: String,
    pub path: String,
    /// Безопасность: none | tls | reality
    pub security: String,
    pub sni: String,
    pub alpn: String,
    pub fingerprint: String,
    pub allow_insecure: bool,
    /// SHA-256 сертификата сервера (pcs / pinnedPeerCertSha256), hex, несколько — через запятую
    pub pinned_cert_sha256: String,
    /// Имена для проверки сертификата вместо SNI (vcn / verifyPeerCertByName)
    pub verify_name: String,
    pub public_key: String,
    pub short_id: String,
    pub spider_x: String,
    /// Обфускация (Hysteria2: salamander)
    pub obfs: String,
    pub obfs_password: String,
    /// Второй секрет (TUIC: пароль)
    pub secret: String,
    /// Результат теста задержки, мс: 0 — не тестировался, -1 — ошибка
    pub delay_ms: i64,
}

impl Profile {
    pub fn new_id() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..12].to_string()
    }
    pub fn display_name(&self) -> String {
        if self.remarks.trim().is_empty() {
            format!("{}:{}", self.address, self.port)
        } else {
            self.remarks.clone()
        }
    }
    pub fn summary(&self) -> String {
        let mut s = self.protocol.name().to_string();
        let net = if self.network.is_empty() { "tcp" } else { &self.network };
        if self.protocol.has_transport() {
            s.push_str(&format!(" · {}", net));
        }
        if self.protocol == Protocol::Hysteria2 && self.obfs == "salamander" {
            s.push_str(" · salamander");
        }
        if !self.security.is_empty() && self.security != "none" {
            s.push_str(&format!(" · {}", self.security));
        }
        if self.protocol == Protocol::Vless && self.method.starts_with("mlkem") {
            s.push_str(" · enc");
        }
        if !self.flow.is_empty() {
            s.push_str(" · vision");
        }
        s
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq)]
#[serde(default)]
pub struct Subscription {
    pub id: String,
    pub remarks: String,
    pub url: String,
    pub enabled: bool,
    pub last_update: i64,
    /// Трафик/срок из заголовка subscription-userinfo
    pub info: String,
    /// Использовано / всего, байт (0 — неизвестно) и срок действия (unix, 0 — бессрочно)
    pub used: u64,
    pub total: u64,
    pub expire: i64,
    /// Название задано пользователем (не перезаписывать profile-title)
    pub custom_name: bool,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum OutboundTag {
    #[default]
    Proxy,
    Direct,
    Block,
}

impl OutboundTag {
    pub fn label(&self) -> &'static str {
        match self {
            OutboundTag::Proxy => "proxy",
            OutboundTag::Direct => "direct",
            OutboundTag::Block => "block",
        }
    }
    pub fn from_index(i: i32) -> Self {
        match i {
            1 => OutboundTag::Direct,
            2 => OutboundTag::Block,
            _ => OutboundTag::Proxy,
        }
    }
    pub fn index(&self) -> i32 {
        match self {
            OutboundTag::Proxy => 0,
            OutboundTag::Direct => 1,
            OutboundTag::Block => 2,
        }
    }
}

/// Правило маршрутизации в стиле Xray/v2rayNG.
#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq)]
#[serde(default)]
pub struct RoutingRule {
    pub id: String,
    pub remarks: String,
    pub enabled: bool,
    pub outbound: OutboundTag,
    /// domain:, full:, keyword:, regexp:, geosite:, или просто подстрока
    pub domain: Vec<String>,
    /// CIDR, одиночный IP, geoip:xx, geoip:private, !geoip:xx
    pub ip: Vec<String>,
    /// "443", "80,443", "1000-2000"
    pub port: String,
    /// "", "tcp", "udp", "tcp,udp"
    pub network: String,
    /// Протокол по сниффингу: http, tls, quic
    pub protocol: Vec<String>,
}

impl RoutingRule {
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        if !self.domain.is_empty() {
            parts.push(format!("домены: {}", self.domain.len()));
        }
        if !self.ip.is_empty() {
            parts.push(format!("IP: {}", self.ip.len()));
        }
        if !self.port.is_empty() {
            parts.push(format!("порт {}", self.port));
        }
        if !self.network.is_empty() {
            parts.push(self.network.clone());
        }
        if !self.protocol.is_empty() {
            parts.push(self.protocol.join(","));
        }
        if parts.is_empty() {
            "все соединения".into()
        } else {
            parts.join(" · ")
        }
    }
}

/// Маршрут на отдельный сервер: трафик выбранных приложений и сайтов идёт
/// через указанный сервер, а не через основной. Проверяется раньше обычных правил.
#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq)]
#[serde(default)]
pub struct SplitRoute {
    pub id: String,
    pub remarks: String,
    pub enabled: bool,
    /// id профиля-сервера
    pub server: String,
    /// Пакеты приложений (Android 10+)
    pub apps: Vec<String>,
    /// Сайты: domain:, full:, keyword:, regexp:, geosite:
    pub domain: Vec<String>,
    /// Сервер недоступен: true — трафик идёт по обычным правилам (через основной сервер),
    /// false — блокируется, чтобы ничего не утекло.
    pub fallback_main: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct RoutingConfig {
    /// AsIs | IPIfNonMatch | IPOnDemand
    pub domain_strategy: String,
    pub rules: Vec<RoutingRule>,
    /// Куда идёт трафик, не попавший ни под одно правило
    pub final_outbound: OutboundTag,
    pub preset: String,
    pub geoip_url: String,
    pub geosite_url: String,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        let mut r = RoutingConfig {
            domain_strategy: "IPIfNonMatch".into(),
            rules: vec![],
            final_outbound: OutboundTag::Proxy,
            preset: String::new(),
            geoip_url: "https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geoip.dat".into(),
            geosite_url: "https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geosite.dat".into(),
        };
        crate::route::presets::apply_preset(&mut r, crate::route::presets::DEFAULT_PRESET);
        r
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Settings {
    pub fake_dns: bool,
    pub sniffing: bool,
    pub ipv6: bool,
    /// DNS для запросов, которые не обрабатывает FakeDNS (MX, TXT и т.п.)
    pub dns_server: String,
    pub mtu: u16,
    pub local_socks: bool,
    pub socks_port: u16,
    pub block_quic: bool,
    /// 0 — выключено, 1 — проксировать только выбранные, 2 — обходить выбранные
    pub per_app_mode: i32,
    pub per_app_list: Vec<String>,
    pub test_url: String,
    pub sub_user_agent: String,
    pub allow_insecure_default: bool,
    /// Обновлять подписки раз в сутки
    pub sub_auto_update: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            fake_dns: true,
            sniffing: true,
            ipv6: true,
            dns_server: "1.1.1.1".into(),
            mtu: 1500,
            local_socks: false,
            socks_port: 10808,
            block_quic: false,
            per_app_mode: 0,
            per_app_list: vec![],
            test_url: "http://www.gstatic.com/generate_204".into(),
            sub_user_agent: "v2rayNG/1.10.0".into(),
            allow_insecure_default: false,
            sub_auto_update: true,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq)]
#[serde(default)]
pub struct AppConfig {
    pub profiles: Vec<Profile>,
    pub selected: String,
    pub subscriptions: Vec<Subscription>,
    pub routing: RoutingConfig,
    /// Маршруты на отдельные серверы
    pub splits: Vec<SplitRoute>,
    pub settings: Settings,
}

impl AppConfig {
    pub fn load(path: &Path) -> AppConfig {
        match std::fs::read_to_string(path) {
            Ok(s) => serde_json::from_str(&s).unwrap_or_else(|e| {
                log::error!("config parse error: {e}");
                AppConfig::default()
            }),
            Err(_) => AppConfig::default(),
        }
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(self).unwrap())?;
        std::fs::rename(&tmp, path)
    }

    pub fn selected_profile(&self) -> Option<&Profile> {
        self.profiles.iter().find(|p| p.id == self.selected)
    }
}
