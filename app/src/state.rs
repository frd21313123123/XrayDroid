//! Состояние приложения и преобразования модели ↔ UI.

use std::path::{Path, PathBuf};

use slint::{ModelRc, SharedString, VecModel};
use xd_core::config::{AppConfig, OutboundTag, Profile, Protocol, RoutingRule};

use crate::{AppItem, ProfileForm, RuleForm, RuleItem, ServerItem, SettingsForm, SubItem};

pub const SS_METHODS: [&str; 6] = [
    "aes-128-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
];
pub const VMESS_METHODS: [&str; 3] = ["auto", "aes-128-gcm", "chacha20-poly1305"];
pub const NETWORKS: [&str; 5] = ["tcp", "ws", "httpupgrade", "grpc", "xhttp"];
pub const SECURITIES: [&str; 3] = ["none", "tls", "reality"];

pub struct State {
    pub cfg: AppConfig,
    pub dir: PathBuf,
    /// "" — все, "manual" — добавленные вручную, иначе id подписки
    pub group: String,
    pub testing: std::collections::HashSet<String>,
    pub apps: Vec<(String, String)>,
    pub apps_loaded: bool,
    pub apps_filter: String,
}

impl State {
    pub fn load(dir: &Path) -> State {
        let cfg = AppConfig::load(&dir.join("config.json"));
        State {
            cfg,
            dir: dir.to_path_buf(),
            group: String::new(),
            testing: Default::default(),
            apps: vec![],
            apps_loaded: false,
            apps_filter: String::new(),
        }
    }

    pub fn save(&self) {
        if let Err(e) = self.cfg.save(&self.dir.join("config.json")) {
            log::error!("не удалось сохранить настройки: {e}");
        }
    }

    pub fn groups(&self) -> Vec<(String, String)> {
        let mut g = vec![(String::new(), "Все".to_string())];
        let has_manual = self.cfg.profiles.iter().any(|p| p.sub_id.is_empty());
        if !self.cfg.subscriptions.is_empty() && has_manual {
            g.push(("manual".into(), "Свои".into()));
        }
        for s in &self.cfg.subscriptions {
            g.push((s.id.clone(), if s.remarks.is_empty() { "Подписка".into() } else { s.remarks.clone() }));
        }
        g
    }

    pub fn in_group(&self, p: &Profile) -> bool {
        match self.group.as_str() {
            "" => true,
            "manual" => p.sub_id.is_empty(),
            g => p.sub_id == g,
        }
    }

    pub fn group_ids(&self) -> Vec<String> {
        self.cfg.profiles.iter().filter(|p| self.in_group(p)).map(|p| p.id.clone()).collect()
    }

    pub fn server_items(&self) -> Vec<ServerItem> {
        self.cfg
            .profiles
            .iter()
            .filter(|p| self.in_group(p))
            .map(|p| {
                let (delay, state) = if self.testing.contains(&p.id) {
                    ("…".to_string(), 4)
                } else if p.delay_ms > 0 {
                    (format!("{} мс", p.delay_ms), if p.delay_ms < 400 { 1 } else if p.delay_ms < 1000 { 2 } else { 3 })
                } else if p.delay_ms < 0 {
                    ("ошибка".to_string(), 3)
                } else {
                    (String::new(), 0)
                };
                ServerItem {
                    id: p.id.clone().into(),
                    name: p.display_name().into(),
                    info: format!("{}:{}", mask_address(&p.address), p.port).into(),
                    kind: p.summary().into(),
                    delay: delay.into(),
                    delay_state: state,
                    selected: p.id == self.cfg.selected,
                }
            })
            .collect()
    }

    pub fn sub_items(&self) -> Vec<SubItem> {
        self.cfg
            .subscriptions
            .iter()
            .map(|s| {
                let count = self.cfg.profiles.iter().filter(|p| p.sub_id == s.id).count();
                let when = if s.last_update > 0 {
                    let ago = now_secs() - s.last_update;
                    if ago < 3600 {
                        format!("обновлена {} мин назад", ago / 60)
                    } else if ago < 86400 {
                        format!("обновлена {} ч назад", ago / 3600)
                    } else {
                        format!("обновлена {} дн назад", ago / 86400)
                    }
                } else {
                    "ещё не обновлялась".into()
                };
                SubItem {
                    id: s.id.clone().into(),
                    name: if s.remarks.is_empty() { "Подписка".into() } else { s.remarks.clone().into() },
                    url: s.url.clone().into(),
                    enabled: s.enabled,
                    info: if s.info.is_empty() {
                        format!("серверов: {count} · {when}")
                    } else {
                        format!("серверов: {count} · {} · {when}", s.info)
                    }
                    .into(),
                }
            })
            .collect()
    }

    pub fn rule_items(&self) -> Vec<RuleItem> {
        self.cfg
            .routing
            .rules
            .iter()
            .map(|r| RuleItem {
                id: r.id.clone().into(),
                name: if r.remarks.is_empty() { "Без названия".into() } else { r.remarks.clone().into() },
                summary: r.summary().into(),
                outbound: r.outbound.index(),
                enabled: r.enabled,
            })
            .collect()
    }

    pub fn app_items(&self) -> Vec<AppItem> {
        let f = self.apps_filter.to_lowercase();
        let sel = &self.cfg.settings.per_app_list;
        let mut v: Vec<AppItem> = self
            .apps
            .iter()
            .filter(|(pkg, label)| f.is_empty() || pkg.to_lowercase().contains(&f) || label.to_lowercase().contains(&f))
            .map(|(pkg, label)| AppItem { pkg: pkg.clone().into(), label: label.clone().into(), checked: sel.contains(pkg) })
            .collect();
        v.sort_by(|a, b| b.checked.cmp(&a.checked).then(a.label.to_lowercase().cmp(&b.label.to_lowercase())));
        v
    }

    pub fn geo_status(&self) -> String {
        let f = |name: &str| match std::fs::metadata(self.dir.join(name)) {
            Ok(m) => format!("{name}: {:.1} МБ", m.len() as f64 / 1048576.0),
            Err(_) => format!("{name}: нет"),
        };
        format!(
            "{}, {}. Нужны для правил geosite:/geoip: (источник — runetfreedom/russia-v2ray-rules-dat).",
            f("geoip.dat"),
            f("geosite.dat")
        )
    }
}

pub fn now_secs() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Скрывает середину адреса, как v2rayNG.
pub fn mask_address(a: &str) -> String {
    if let Ok(ip) = a.parse::<std::net::Ipv4Addr>() {
        let o = ip.octets();
        return format!("{}.{}.*.*", o[0], o[1]);
    }
    if a.len() > 12 {
        let chars: Vec<char> = a.chars().collect();
        let n = chars.len();
        let head: String = chars[..4].iter().collect();
        let tail: String = chars[n - 6..].iter().collect();
        return format!("{head}…{tail}");
    }
    a.to_string()
}

pub fn model<T: Clone + 'static>(v: Vec<T>) -> ModelRc<T> {
    ModelRc::new(VecModel::from(v))
}

pub fn strings(v: Vec<String>) -> ModelRc<SharedString> {
    ModelRc::new(VecModel::from(v.into_iter().map(SharedString::from).collect::<Vec<_>>()))
}

fn proto_index(p: Protocol) -> i32 {
    Protocol::all().iter().position(|x| *x == p).unwrap_or(0) as i32
}

pub fn profile_to_form(p: &Profile) -> ProfileForm {
    let method_index = match p.protocol {
        Protocol::Shadowsocks => SS_METHODS.iter().position(|m| *m == p.method).unwrap_or(0),
        Protocol::Vmess => VMESS_METHODS.iter().position(|m| *m == p.method).unwrap_or(0),
        _ => 0,
    } as i32;
    ProfileForm {
        id: p.id.clone().into(),
        protocol: proto_index(p.protocol),
        remarks: p.remarks.clone().into(),
        address: p.address.clone().into(),
        port: if p.port == 0 { SharedString::new() } else { p.port.to_string().into() },
        uuid: p.id_or_password.clone().into(),
        username: p.username.clone().into(),
        method: p.method.clone().into(),
        method_index,
        flow: if p.flow.starts_with("xtls-rprx-vision") { 1 } else { 0 },
        network: NETWORKS.iter().position(|n| *n == p.network.as_str()).unwrap_or(0) as i32,
        header_type: p.header_type.clone().into(),
        host: p.host.clone().into(),
        path: p.path.clone().into(),
        security: SECURITIES.iter().position(|n| *n == p.security.as_str()).unwrap_or(0) as i32,
        sni: p.sni.clone().into(),
        alpn: p.alpn.clone().into(),
        fingerprint: p.fingerprint.clone().into(),
        allow_insecure: p.allow_insecure,
        public_key: p.public_key.clone().into(),
        short_id: p.short_id.clone().into(),
        spider_x: p.spider_x.clone().into(),
    }
}

/// Проверка и преобразование формы. Возвращает ошибку для пользователя.
pub fn form_to_profile(f: &ProfileForm, base: Option<&Profile>) -> Result<Profile, String> {
    let protocol = Protocol::all()[f.protocol.clamp(0, 4) as usize];
    let mut p = base.cloned().unwrap_or_default();
    if p.id.is_empty() {
        p.id = Profile::new_id();
    }
    p.protocol = protocol;
    p.remarks = f.remarks.trim().to_string();
    p.address = f.address.trim().to_string();
    if p.address.is_empty() {
        return Err("Укажите адрес сервера".into());
    }
    p.port = f.port.trim().parse::<u16>().ok().filter(|p| *p > 0).ok_or("Порт должен быть числом от 1 до 65535")?;
    p.id_or_password = f.uuid.trim().to_string();
    match protocol {
        Protocol::Vless | Protocol::Vmess => {
            if xd_core::proxy::vless::parse_uuid(&p.id_or_password).is_err() {
                return Err("Неверный UUID".into());
            }
        }
        Protocol::Trojan | Protocol::Shadowsocks => {
            if p.id_or_password.is_empty() {
                return Err("Укажите пароль".into());
            }
        }
        Protocol::Socks => {}
    }
    p.username = f.username.trim().to_string();
    p.method = match protocol {
        Protocol::Shadowsocks => SS_METHODS[f.method_index.clamp(0, 5) as usize].to_string(),
        Protocol::Vmess => VMESS_METHODS[f.method_index.clamp(0, 2) as usize].to_string(),
        Protocol::Vless => "none".into(),
        _ => String::new(),
    };
    p.flow = if protocol == Protocol::Vless && f.flow == 1 { "xtls-rprx-vision".into() } else { String::new() };
    let stream = matches!(protocol, Protocol::Vless | Protocol::Vmess | Protocol::Trojan);
    p.network = if stream { NETWORKS[f.network.clamp(0, 4) as usize].into() } else { "tcp".into() };
    p.security = if stream { SECURITIES[f.security.clamp(0, 2) as usize].into() } else { "none".into() };
    if p.security == "reality" && protocol != Protocol::Vless {
        return Err("REALITY поддерживается только с VLESS".into());
    }
    p.header_type = f.header_type.to_string();
    p.host = f.host.trim().to_string();
    p.path = f.path.trim().to_string();
    p.sni = f.sni.trim().to_string();
    p.alpn = f.alpn.trim().to_string();
    p.fingerprint = f.fingerprint.trim().to_string();
    p.allow_insecure = f.allow_insecure;
    p.public_key = f.public_key.trim().to_string();
    p.short_id = f.short_id.trim().to_string();
    p.spider_x = f.spider_x.trim().to_string();
    if p.security == "reality" && p.public_key.is_empty() {
        return Err("Для REALITY нужен publicKey".into());
    }
    if p.flow.is_empty() && base.map(|b| b.flow != p.flow).unwrap_or(false) {
        // flow сброшен вручную — ок
    }
    if p.flow.starts_with("xtls") && p.security != "reality" {
        return Err("Vision в этом клиенте работает только с REALITY".into());
    }
    Ok(p)
}

pub fn new_form(protocol: i32, allow_insecure: bool) -> ProfileForm {
    let mut f = profile_to_form(&Profile { port: 443, ..Default::default() });
    f.protocol = protocol;
    f.security = match protocol {
        2 => 1,
        _ => 0,
    };
    f.allow_insecure = allow_insecure;
    if protocol == 0 {
        f.fingerprint = "chrome".into();
    }
    f
}

pub fn rule_to_form(r: &RoutingRule) -> RuleForm {
    RuleForm {
        id: r.id.clone().into(),
        name: r.remarks.clone().into(),
        outbound: r.outbound.index(),
        enabled: r.enabled,
        domain: r.domain.join("\n").into(),
        ip: r.ip.join("\n").into(),
        port: r.port.clone().into(),
        network: match r.network.as_str() {
            "tcp" => 1,
            "udp" => 2,
            _ => 0,
        },
        protocol: r.protocol.join(",").into(),
    }
}

pub fn form_to_rule(f: &RuleForm) -> RoutingRule {
    let lines = |s: &str| -> Vec<String> {
        s.split(['\n', ','])
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect()
    };
    RoutingRule {
        id: if f.id.is_empty() { Profile::new_id() } else { f.id.to_string() },
        remarks: f.name.trim().to_string(),
        enabled: f.enabled,
        outbound: OutboundTag::from_index(f.outbound),
        domain: lines(&f.domain),
        ip: lines(&f.ip),
        port: f.port.trim().to_string(),
        network: match f.network {
            1 => "tcp".into(),
            2 => "udp".into(),
            _ => String::new(),
        },
        protocol: f.protocol.split(',').map(|s| s.trim().to_lowercase()).filter(|s| !s.is_empty()).collect(),
    }
}

pub fn settings_to_form(s: &xd_core::config::Settings) -> SettingsForm {
    SettingsForm {
        fake_dns: s.fake_dns,
        sniffing: s.sniffing,
        ipv6: s.ipv6,
        local_socks: s.local_socks,
        socks_port: s.socks_port.to_string().into(),
        block_quic: s.block_quic,
        allow_insecure: s.allow_insecure_default,
        dns: s.dns_server.clone().into(),
        mtu: s.mtu.to_string().into(),
        test_url: s.test_url.clone().into(),
        ua: s.sub_user_agent.clone().into(),
    }
}

pub fn form_to_settings(f: &SettingsForm, s: &mut xd_core::config::Settings) {
    s.fake_dns = f.fake_dns;
    s.sniffing = f.sniffing;
    s.ipv6 = f.ipv6;
    s.local_socks = f.local_socks;
    if let Ok(p) = f.socks_port.trim().parse::<u16>() {
        if p > 0 {
            s.socks_port = p;
        }
    }
    s.block_quic = f.block_quic;
    s.allow_insecure_default = f.allow_insecure;
    if !f.dns.trim().is_empty() {
        s.dns_server = f.dns.trim().to_string();
    }
    if let Ok(m) = f.mtu.trim().parse::<u16>() {
        s.mtu = m.clamp(1280, 9000);
    }
    if !f.test_url.trim().is_empty() {
        s.test_url = f.test_url.trim().to_string();
    }
    if !f.ua.trim().is_empty() {
        s.sub_user_agent = f.ua.trim().to_string();
    }
}

/// Ключ для поиска дубликатов: ссылка без названия.
pub fn dedup_key(p: &Profile) -> String {
    let mut c = p.clone();
    c.remarks.clear();
    c.id.clear();
    c.sub_id.clear();
    c.delay_ms = 0;
    xd_core::links::to_link(&c)
}
