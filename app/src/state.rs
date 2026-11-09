//! Состояние приложения и преобразования модели ↔ UI.

use std::path::{Path, PathBuf};

use slint::{Color, ModelRc, SharedString, VecModel};
use xd_core::config::{AppConfig, OutboundTag, Profile, Protocol, RoutingRule, SplitRoute};

use crate::{AppBadge, AppItem, ProfileForm, RuleForm, RuleItem, ServerItem, SettingsForm, SplitForm, SplitItem, SubItem};

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

/// Сколько приложений показывать в списке сразу (остальные — через поиск).
pub const APPS_SHOWN: usize = 60;

pub struct State {
    pub cfg: AppConfig,
    pub dir: PathBuf,
    /// "" — все, "manual" — добавленные вручную, иначе id подписки
    pub group: String,
    pub testing: std::collections::HashSet<String>,
    pub apps: Vec<(String, String)>,
    pub apps_loaded: bool,
    pub apps_filter: String,
    /// Редактируемый маршрут на отдельный сервер: выбранные приложения, сервер и фильтр
    pub split_apps: std::collections::BTreeSet<String>,
    pub split_server: String,
    pub split_filter: String,
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
            split_apps: Default::default(),
            split_server: String::new(),
            split_filter: String::new(),
        }
    }

    pub fn save(&self) {
        if let Err(e) = self.cfg.save(&self.dir.join("config.json")) {
            log::error!("не удалось сохранить настройки: {e}");
        }
    }

    pub fn groups(&self) -> Vec<(String, String)> {
        let mut g = vec![(String::new(), format!("Все · {}", self.cfg.profiles.len()))];
        let has_manual = self.cfg.profiles.iter().any(|p| p.sub_id.is_empty());
        if !self.cfg.subscriptions.is_empty() && has_manual {
            g.push(("manual".into(), "Мои".into()));
        }
        for s in &self.cfg.subscriptions {
            g.push((s.id.clone(), if s.remarks.is_empty() { "Подписка".into() } else { crate::fonts::text(&s.remarks) }));
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

    /// Текущая вкладка — группа без ссылки (созданная вручную): новые серверы попадают в неё.
    pub fn local_group(&self) -> Option<String> {
        self.cfg
            .subscriptions
            .iter()
            .find(|s| s.id == self.group && s.url.trim().is_empty())
            .map(|s| s.id.clone())
    }

    pub fn group_ids(&self) -> Vec<String> {
        self.cfg.profiles.iter().filter(|p| self.in_group(p)).map(|p| p.id.clone()).collect()
    }

    pub fn server_items(&self) -> Vec<ServerItem> {
        self.cfg.profiles.iter().filter(|p| self.in_group(p)).map(|p| self.server_item(p, p.id == self.cfg.selected)).collect()
    }

    pub fn server_item(&self, p: &Profile, selected: bool) -> ServerItem {
        let (delay, state) = if self.testing.contains(&p.id) {
            ("…".to_string(), 4)
        } else if p.delay_ms > 0 {
            (format!("{} мс", p.delay_ms), if p.delay_ms < 100 { 1 } else if p.delay_ms < 250 { 2 } else { 3 })
        } else if p.delay_ms < 0 {
            ("ошибка".to_string(), 3)
        } else {
            ("—".to_string(), 0)
        };
        ServerItem { id: p.id.clone().into(), name: crate::fonts::text(&p.display_name()).into(), kind: kind_label(p).into(), delay: delay.into(), delay_state: state, selected }
    }

    /// Все серверы для выбора в маршруте на отдельный сервер.
    pub fn split_server_items(&self) -> Vec<ServerItem> {
        self.cfg.profiles.iter().map(|p| self.server_item(p, p.id == self.split_server)).collect()
    }

    pub fn sub_items(&self) -> Vec<SubItem> {
        self.cfg
            .subscriptions
            .iter()
            .map(|s| {
                let count = self.cfg.profiles.iter().filter(|p| p.sub_id == s.id).count();
                let local = s.url.trim().is_empty();
                let when = if local {
                    "Группа без ссылки — серверы добавляются вручную".to_string()
                } else if s.last_update > 0 {
                    let ago = now_secs() - s.last_update;
                    if ago < 120 {
                        "Обновлено только что".to_string()
                    } else if ago < 3600 {
                        format!("Обновлено {} мин назад", ago / 60)
                    } else if ago < 86400 {
                        format!("Обновлено {} ч назад", ago / 3600)
                    } else if ago < 2 * 86400 {
                        "Обновлено вчера".to_string()
                    } else {
                        format!("Обновлено {} дн назад", ago / 86400)
                    }
                } else {
                    "Ещё не обновлялась".into()
                };
                let ratio = if s.total > 0 { (s.used as f64 / s.total as f64).clamp(0.0, 1.0) as f32 } else { 0.0 };
                SubItem {
                    id: s.id.clone().into(),
                    name: if s.remarks.is_empty() { "Подписка".into() } else { crate::fonts::text(&s.remarks).into() },
                    url: if local { "без ссылки".into() } else { s.url.clone().into() },
                    local,
                    enabled: s.enabled,
                    count: format!("{count} серв.").into(),
                    has_usage: s.total > 0,
                    ratio,
                    warn: ratio > 0.8,
                    used: format!("{} / {} ГБ", gb(s.used), gb(s.total)).into(),
                    expire: expire_label(s.expire).into(),
                    updated: when.into(),
                }
            })
            .collect()
    }

    pub fn rule_items(&self) -> Vec<RuleItem> {
        self.cfg
            .routing
            .rules
            .iter()
            .map(|r| {
                let list: Vec<&str> = r.domain.iter().chain(r.ip.iter()).map(|s| s.as_str()).collect();
                RuleItem {
                    id: r.id.clone().into(),
                    cond: if list.is_empty() { r.summary() } else { list.join(", ") }.into(),
                    outbound: r.outbound.index(),
                    enabled: r.enabled,
                }
            })
            .collect()
    }

    /// Установленное приложение по пакету: название (или производное от пакета).
    pub fn app_label(&self, pkg: &str) -> String {
        self.apps.iter().find(|(p, _)| p == pkg).map(|(_, l)| l.clone()).unwrap_or_else(|| {
            let last = pkg.rsplit('.').next().unwrap_or(pkg);
            let mut c = last.chars();
            c.next().map(|f| f.to_uppercase().collect::<String>() + c.as_str()).unwrap_or_default()
        })
    }

    pub fn split_items(&self) -> Vec<SplitItem> {
        self.cfg
            .splits
            .iter()
            .map(|sp| {
                let badges: Vec<AppBadge> = sp
                    .apps
                    .iter()
                    .take(3)
                    .map(|pkg| AppBadge { letter: app_letter(&self.app_label(pkg)).into(), tint: app_tint(pkg) })
                    .collect();
                let d = sp.domain.len();
                let meta = match (sp.apps.len(), d) {
                    (0, 0) => "ничего не выбрано".to_string(),
                    (0, d) => format!("{d} {}", plural(d, "сайт", "сайта", "сайтов")),
                    (a, 0) => format!("{a} прил."),
                    (a, d) if a <= 3 => format!("+ {d} {}", plural(d, "сайт", "сайта", "сайтов")),
                    (a, d) => format!("{a} прил. · {d} {}", plural(d, "сайт", "сайта", "сайтов")),
                };
                SplitItem {
                    id: sp.id.clone().into(),
                    name: if sp.remarks.trim().is_empty() { "Без названия".into() } else { sp.remarks.clone().into() },
                    server: self
                        .cfg
                        .profiles
                        .iter()
                        .find(|p| p.id == sp.server)
                        .map(|p| crate::fonts::text(&p.display_name()))
                        .unwrap_or_else(|| "сервер не выбран".into())
                        .into(),
                    apps: model(badges),
                    meta: meta.into(),
                    enabled: sp.enabled,
                }
            })
            .collect()
    }

    /// Приложения для списка в маршруте на отдельный сервер: выбранные сверху, фильтр по тексту.
    pub fn split_app_items(&self) -> (Vec<AppItem>, String) {
        app_list(&self.apps, &self.split_filter, |pkg| self.split_apps.contains(pkg))
    }

    pub fn apps_summary(&self) -> String {
        let n = self.cfg.settings.per_app_list.len();
        match self.cfg.settings.per_app_mode {
            1 => format!("выбрано {n}"),
            2 => format!("кроме {n}"),
            _ => "все".into(),
        }
    }

    pub fn app_items(&self) -> (Vec<AppItem>, String) {
        let sel = &self.cfg.settings.per_app_list;
        app_list(&self.apps, &self.apps_filter, |pkg| sel.iter().any(|p| p == pkg))
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

/// Список приложений для экрана: выбранные сверху, остальные по алфавиту; не больше APPS_SHOWN строк.
fn app_list(apps: &[(String, String)], filter: &str, checked: impl Fn(&str) -> bool) -> (Vec<AppItem>, String) {
    let f = filter.trim().to_lowercase();
    let mut v: Vec<AppItem> = apps
        .iter()
        .filter(|(pkg, label)| f.is_empty() || pkg.to_lowercase().contains(&f) || label.to_lowercase().contains(&f))
        .map(|(pkg, label)| AppItem {
            pkg: pkg.clone().into(),
            label: label.clone().into(),
            checked: checked(pkg),
            letter: app_letter(label).into(),
            tint: app_tint(pkg),
        })
        .collect();
    v.sort_by(|a, b| b.checked.cmp(&a.checked).then(a.label.to_lowercase().cmp(&b.label.to_lowercase())));
    let total = v.len();
    let selected = v.iter().filter(|a| a.checked).count();
    let shown = APPS_SHOWN.max(selected);
    let more = if total > shown { format!("Показано {shown} из {total} — уточните поиск") } else { String::new() };
    v.truncate(shown);
    (v, more)
}

/// Первая буква названия для плитки приложения.
pub fn app_letter(label: &str) -> String {
    label.chars().find(|c| c.is_alphanumeric()).map(|c| c.to_uppercase().collect()).unwrap_or_else(|| "?".into())
}

/// Цвет плитки приложения — стабильный по имени пакета.
pub fn app_tint(pkg: &str) -> Color {
    const PALETTE: [(u8, u8, u8); 8] = [
        (0x3f, 0x3f, 0x3a),
        (0x1d, 0x4e, 0xd8),
        (0x5b, 0x4b, 0xc4),
        (0x2a, 0x8b, 0xc4),
        (0xa1, 0x5c, 0x00),
        (0x2f, 0x5d, 0x8a),
        (0x0f, 0x7a, 0x3d),
        (0x0f, 0x76, 0x6e),
    ];
    let h = pkg.bytes().fold(5381u32, |h, b| h.wrapping_mul(33).wrapping_add(b as u32));
    let (r, g, b) = PALETTE[(h % 8) as usize];
    Color::from_rgb_u8(r, g, b)
}

pub fn plural(n: usize, one: &'static str, few: &'static str, many: &'static str) -> &'static str {
    match (n % 10, n % 100) {
        (_, 11..=14) => many,
        (1, _) => one,
        (2..=4, _) => few,
        _ => many,
    }
}

/// Короткое описание сервера для списка: «VLESS · REALITY · Vision».
pub fn kind_label(p: &Profile) -> String {
    let mut parts: Vec<String> = Vec::new();
    match p.protocol {
        Protocol::Hysteria2 => {
            parts.push("Hysteria2".into());
            if p.obfs == "salamander" {
                parts.push("Salamander".into());
            }
        }
        Protocol::Tuic => parts.push("TUIC v5".into()),
        Protocol::Shadowsocks => parts.push(if p.method.starts_with("2022") { "Shadowsocks 2022".into() } else { "Shadowsocks".into() }),
        Protocol::Vless | Protocol::Vmess | Protocol::Trojan => {
            parts.push(p.protocol.name().into());
            match p.network.as_str() {
                "ws" => parts.push("WS".into()),
                "grpc" => parts.push("gRPC".into()),
                "xhttp" => parts.push("XHTTP".into()),
                "httpupgrade" => parts.push("HTTPUpgrade".into()),
                _ => {}
            }
            match p.security.as_str() {
                "reality" => parts.push("REALITY".into()),
                "tls" => parts.push("TLS".into()),
                _ => {}
            }
            if p.protocol == Protocol::Vless {
                if p.method.starts_with("mlkem") {
                    parts.push("Enc".into());
                }
                if p.flow.starts_with("xtls") {
                    parts.push("Vision".into());
                }
            }
        }
        _ => parts.push(p.protocol.name().into()),
    }
    parts.join(" · ")
}

/// Гигабайты по-русски: «34,2», «100».
pub fn gb(bytes: u64) -> String {
    let v = bytes as f64 / 1073741824.0;
    let s = if v >= 100.0 || (v - v.round()).abs() < 0.05 { format!("{:.0}", v) } else { format!("{:.1}", v) };
    s.replace('.', ",")
}

/// «до 12 дек 2026» / «истекла» / «» (бессрочная).
pub fn expire_label(expire: i64) -> String {
    if expire <= 0 {
        return String::new();
    }
    if expire < now_secs() {
        return "истекла".into();
    }
    // дата по григорианскому календарю (алгоритм Говарда Хиннанта)
    let z = expire / 86400 + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + if month <= 2 { 1 } else { 0 };
    const M: [&str; 12] = ["янв", "фев", "мар", "апр", "мая", "июн", "июл", "авг", "сен", "окт", "ноя", "дек"];
    format!("до {day} {} {year}", M[(month - 1) as usize])
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
        flow: match p.flow.as_str() {
            "xtls-rprx-vision" => 1,
            "xtls-rprx-vision-udp443" => 2,
            _ => 0,
        },
        network: NETWORKS.iter().position(|n| *n == p.network.as_str()).unwrap_or(0) as i32,
        header_type: p.header_type.clone().into(),
        host: p.host.clone().into(),
        path: p.path.clone().into(),
        security: SECURITIES.iter().position(|n| *n == p.security.as_str()).unwrap_or(0) as i32,
        sni: p.sni.clone().into(),
        alpn: p.alpn.clone().into(),
        fingerprint: p.fingerprint.clone().into(),
        allow_insecure: p.allow_insecure,
        pinned_cert: p.pinned_cert_sha256.clone().into(),
        public_key: p.public_key.clone().into(),
        short_id: p.short_id.clone().into(),
        spider_x: p.spider_x.clone().into(),
        obfs: if p.obfs == "salamander" { 1 } else { 0 },
        obfs_password: p.obfs_password.clone().into(),
        secret: p.secret.clone().into(),
    }
}

/// Проверка и преобразование формы. Возвращает ошибку для пользователя.
pub fn form_to_profile(f: &ProfileForm, base: Option<&Profile>) -> Result<Profile, String> {
    let protocol = Protocol::all()[f.protocol.clamp(0, 8) as usize];
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
        Protocol::Vless | Protocol::Vmess | Protocol::Tuic => {
            if xd_core::proxy::vless::parse_uuid(&p.id_or_password).is_err() {
                return Err("Неверный UUID".into());
            }
        }
        Protocol::Trojan | Protocol::Shadowsocks | Protocol::Hysteria2 | Protocol::AnyTls => {
            if p.id_or_password.is_empty() {
                return Err("Укажите пароль".into());
            }
        }
        Protocol::Socks | Protocol::Http => {}
    }
    p.username = f.username.trim().to_string();
    p.method = match protocol {
        Protocol::Shadowsocks => SS_METHODS[f.method_index.clamp(0, 5) as usize].to_string(),
        Protocol::Vmess => VMESS_METHODS[f.method_index.clamp(0, 2) as usize].to_string(),
        Protocol::Vless => {
            let m = f.method.trim();
            if m.is_empty() { "none".into() } else { m.to_string() }
        }
        _ => String::new(),
    };
    p.flow = match (protocol, f.flow) {
        (Protocol::Vless, 1) => "xtls-rprx-vision".into(),
        (Protocol::Vless, 2) => "xtls-rprx-vision-udp443".into(),
        _ => String::new(),
    };
    if protocol == Protocol::Vless {
        if let Err(e) = xd_core::proxy::vless_enc::parse(&p.method) {
            return Err(e.to_string());
        }
    }
    let stream = protocol.has_transport();
    p.network = if stream { NETWORKS[f.network.clamp(0, 4) as usize].into() } else { "tcp".into() };
    p.security = match protocol {
        _ if stream => SECURITIES[f.security.clamp(0, 2) as usize].into(),
        Protocol::Hysteria2 | Protocol::Tuic | Protocol::AnyTls => "tls".into(),
        Protocol::Http => SECURITIES[f.security.clamp(0, 1) as usize].into(),
        _ => "none".into(),
    };
    p.obfs = if protocol == Protocol::Hysteria2 && f.obfs == 1 { "salamander".into() } else { String::new() };
    p.obfs_password = if p.obfs.is_empty() { String::new() } else { f.obfs_password.to_string() };
    p.secret = if protocol == Protocol::Tuic { f.secret.to_string() } else { String::new() };
    if protocol == Protocol::Tuic && p.secret.is_empty() {
        return Err("Укажите пароль TUIC".into());
    }
    if p.security == "reality" && protocol != Protocol::Vless {
        return Err("REALITY поддерживается только с VLESS".into());
    }
    let ht = f.header_type.to_string();
    p.header_type = match p.network.as_str() {
        "tcp" if ht == "http" => ht,
        "grpc" if ht == "multi" || ht == "gun" => ht,
        "xhttp" if ["auto", "stream-one", "stream-up", "packet-up"].contains(&ht.as_str()) => ht,
        _ => String::new(),
    };
    p.host = f.host.trim().to_string();
    p.path = f.path.trim().to_string();
    p.sni = f.sni.trim().to_string();
    p.alpn = f.alpn.trim().to_string();
    p.fingerprint = f.fingerprint.trim().to_string();
    p.allow_insecure = f.allow_insecure;
    p.pinned_cert_sha256 = f.pinned_cert.trim().to_string();
    if !p.pinned_cert_sha256.is_empty()
        && xd_core::transport::certs::parse_pins(&p.pinned_cert_sha256).len()
            != p.pinned_cert_sha256.split(',').filter(|v| !v.trim().is_empty()).count()
    {
        return Err("SHA-256 сертификата: 64 hex-символа (можно с двоеточиями), несколько — через запятую".into());
    }
    p.public_key = f.public_key.trim().to_string();
    p.short_id = f.short_id.trim().to_string();
    p.spider_x = f.spider_x.trim().to_string();
    if p.security == "reality" && p.public_key.is_empty() {
        return Err("Для REALITY нужен publicKey".into());
    }
    if p.flow.is_empty() && base.map(|b| b.flow != p.flow).unwrap_or(false) {
        // flow сброшен вручную — ок
    }
    let has_enc = p.method != "none" && !p.method.is_empty() && protocol == Protocol::Vless;
    if p.flow.starts_with("xtls") && !has_enc && (p.security == "none" || p.network != "tcp") {
        return Err("Vision требует TLS или REALITY с транспортом TCP, либо VLESS Encryption".into());
    }
    Ok(p)
}

pub fn new_form(protocol: i32, allow_insecure: bool) -> ProfileForm {
    let mut f = profile_to_form(&Profile { port: 443, ..Default::default() });
    f.protocol = protocol;
    f.security = match protocol {
        2 | 5 | 6 | 7 => 1,
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

pub fn split_to_form(sp: &SplitRoute) -> SplitForm {
    SplitForm {
        id: sp.id.clone().into(),
        name: sp.remarks.clone().into(),
        server: sp.server.clone().into(),
        domain: sp.domain.join("\n").into(),
        fallback_main: sp.fallback_main,
    }
}

/// Преобразует форму и выбранные приложения в маршрут. Ошибка — текст для пользователя.
pub fn form_to_split(f: &SplitForm, server: &str, apps: &std::collections::BTreeSet<String>, enabled: bool) -> Result<SplitRoute, String> {
    let domain: Vec<String> =
        f.domain.split(['\n', ',']).map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect();
    if server.is_empty() {
        return Err("Выберите сервер".into());
    }
    if apps.is_empty() && domain.is_empty() {
        return Err("Выберите приложения или укажите сайты".into());
    }
    Ok(SplitRoute {
        id: if f.id.is_empty() { Profile::new_id() } else { f.id.to_string() },
        remarks: f.name.trim().to_string(),
        enabled,
        server: server.to_string(),
        apps: apps.iter().cloned().collect(),
        domain,
        fallback_main: f.fallback_main,
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats() {
        assert_eq!(gb((34.2 * 1073741824.0) as u64), "34,2");
        assert_eq!(gb(86 * 1073741824), "86");
        assert_eq!(gb(100 * 1073741824), "100");
        assert_eq!(plural(1, "сайт", "сайта", "сайтов"), "сайт");
        assert_eq!(plural(4, "сайт", "сайта", "сайтов"), "сайта");
        assert_eq!(plural(11, "сайт", "сайта", "сайтов"), "сайтов");
        assert_eq!(plural(21, "сайт", "сайта", "сайтов"), "сайт");
        assert_eq!(expire_label(0), "");
        assert_eq!(expire_label(1), "истекла");
        // 2100-01-01 00:00:00 UTC — дата в будущем при любом запуске теста
        assert_eq!(expire_label(4_102_444_800), "до 1 янв 2100");
        assert_eq!(app_letter("ChatGPT"), "C");
        assert_eq!(app_letter("яндекс"), "Я");
    }

    #[test]
    fn server_kind() {
        let mut p = Profile { protocol: Protocol::Vless, network: "tcp".into(), security: "reality".into(), flow: "xtls-rprx-vision".into(), ..Default::default() };
        assert_eq!(kind_label(&p), "VLESS · REALITY · Vision");
        p.network = "xhttp".into();
        p.security = "tls".into();
        p.flow.clear();
        assert_eq!(kind_label(&p), "VLESS · XHTTP · TLS");
        let h = Profile { protocol: Protocol::Hysteria2, obfs: "salamander".into(), ..Default::default() };
        assert_eq!(kind_label(&h), "Hysteria2 · Salamander");
        let ss = Profile { protocol: Protocol::Shadowsocks, method: "2022-blake3-aes-128-gcm".into(), ..Default::default() };
        assert_eq!(kind_label(&ss), "Shadowsocks 2022");
    }

    #[test]
    fn split_form_validation() {
        let f = SplitForm { id: "".into(), name: "Н".into(), server: "".into(), domain: "domain:a.com\n\n keyword:b ".into(), fallback_main: true };
        let apps = std::collections::BTreeSet::new();
        assert!(form_to_split(&f, "", &apps, true).is_err());
        let sp = form_to_split(&f, "srv", &apps, true).unwrap();
        assert_eq!(sp.domain, vec!["domain:a.com", "keyword:b"]);
        assert!(sp.fallback_main && sp.enabled && !sp.id.is_empty());
        let f2 = SplitForm { domain: "".into(), ..f };
        assert!(form_to_split(&f2, "srv", &apps, true).is_err());
        let mut apps = apps;
        apps.insert("com.x".to_string());
        assert_eq!(form_to_split(&f2, "srv", &apps, true).unwrap().apps, vec!["com.x"]);
    }
}
