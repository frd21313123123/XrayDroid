//! Маршрутизация: правила в стиле Xray с поддержкой geosite/geoip.

pub mod geo;
pub mod presets;

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use regex::Regex;

use crate::common::Network;
use crate::config::{OutboundTag, RoutingConfig, RoutingRule};

#[derive(Default)]
struct DomainMatcher {
    full: HashSet<String>,
    suffix: HashSet<String>,
    keywords: Vec<String>,
    regexes: Vec<Regex>,
}

impl DomainMatcher {
    fn is_empty(&self) -> bool {
        self.full.is_empty() && self.suffix.is_empty() && self.keywords.is_empty() && self.regexes.is_empty()
    }
    fn add(&mut self, kind: u8, v: &str) {
        let v = v.trim().trim_end_matches('.').to_ascii_lowercase();
        if v.is_empty() {
            return;
        }
        match kind {
            0 => self.keywords.push(v),
            1 => match Regex::new(&v) {
                Ok(r) => self.regexes.push(r),
                Err(e) => log::warn!("неверный regexp {v}: {e}"),
            },
            2 => {
                self.suffix.insert(v);
            }
            _ => {
                self.full.insert(v);
            }
        }
    }
    fn matches(&self, domain: &str) -> bool {
        let d = domain.trim_end_matches('.').to_ascii_lowercase();
        if self.full.contains(&d) {
            return true;
        }
        if !self.suffix.is_empty() {
            let mut rest = d.as_str();
            loop {
                if self.suffix.contains(rest) {
                    return true;
                }
                match rest.find('.') {
                    Some(i) => rest = &rest[i + 1..],
                    None => break,
                }
            }
        }
        self.keywords.iter().any(|k| d.contains(k.as_str())) || self.regexes.iter().any(|r| r.is_match(&d))
    }
}

#[derive(Default)]
struct IpMatcher {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
    reverse_v4: Vec<(u32, u32)>,
    reverse_v6: Vec<(u128, u128)>,
    has_reverse: bool,
}

fn merge<T: Ord + Copy + num_like::One>(mut v: Vec<(T, T)>) -> Vec<(T, T)> {
    v.sort();
    let mut out: Vec<(T, T)> = Vec::with_capacity(v.len());
    for (s, e) in v {
        if let Some(last) = out.last_mut() {
            if s <= last.1 || last.1.succ() == s {
                if e > last.1 {
                    last.1 = e;
                }
                continue;
            }
        }
        out.push((s, e));
    }
    out
}

mod num_like {
    pub trait One {
        fn succ(self) -> Self;
    }
    impl One for u32 {
        fn succ(self) -> Self {
            self.saturating_add(1)
        }
    }
    impl One for u128 {
        fn succ(self) -> Self {
            self.saturating_add(1)
        }
    }
}

fn in_ranges<T: Ord + Copy>(r: &[(T, T)], x: T) -> bool {
    match r.binary_search_by(|(s, _)| s.cmp(&x)) {
        Ok(_) => true,
        Err(0) => false,
        Err(i) => r[i - 1].1 >= x,
    }
}

impl IpMatcher {
    fn add(&mut self, ip: IpAddr, prefix: u8, reverse: bool) {
        match ip {
            IpAddr::V4(v4) => {
                let p = prefix.min(32) as u32;
                let base = u32::from(v4);
                let mask = if p == 0 { 0 } else { u32::MAX << (32 - p) };
                let s = base & mask;
                let e = s | !mask;
                if reverse { self.reverse_v4.push((s, e)) } else { self.v4.push((s, e)) }
            }
            IpAddr::V6(v6) => {
                let p = prefix.min(128) as u32;
                let base = u128::from(v6);
                let mask = if p == 0 { 0 } else { u128::MAX << (128 - p) };
                let s = base & mask;
                let e = s | !mask;
                if reverse { self.reverse_v6.push((s, e)) } else { self.v6.push((s, e)) }
            }
        }
        if reverse {
            self.has_reverse = true;
        }
    }
    fn finish(&mut self) {
        self.v4 = merge(std::mem::take(&mut self.v4));
        self.v6 = merge(std::mem::take(&mut self.v6));
        self.reverse_v4 = merge(std::mem::take(&mut self.reverse_v4));
        self.reverse_v6 = merge(std::mem::take(&mut self.reverse_v6));
    }
    fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty() && !self.has_reverse
    }
    fn matches(&self, ip: IpAddr) -> bool {
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
            x => x,
        };
        match ip {
            IpAddr::V4(v4) => {
                let x = u32::from(v4);
                in_ranges(&self.v4, x) || (self.has_reverse && !in_ranges(&self.reverse_v4, x))
            }
            IpAddr::V6(v6) => {
                let x = u128::from(v6);
                in_ranges(&self.v6, x) || (self.has_reverse && !in_ranges(&self.reverse_v6, x))
            }
        }
    }
}

pub const PRIVATE_CIDRS: &[&str] = &[
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
    "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
    "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32", "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
];

pub fn parse_cidr(s: &str) -> Option<(IpAddr, u8)> {
    let s = s.trim();
    match s.split_once('/') {
        Some((ip, p)) => {
            let ip: IpAddr = ip.trim().parse().ok()?;
            Some((ip, p.trim().parse().ok()?))
        }
        None => {
            let ip: IpAddr = s.parse().ok()?;
            Some((ip, if ip.is_ipv4() { 32 } else { 128 }))
        }
    }
}

/// Компилирует список доменных условий (`domain:`, `full:`, `keyword:`, `regexp:`, `geosite:`).
fn compile_domains(list: &[String], sites: &HashMap<String, Vec<geo::GeoDomain>>) -> DomainMatcher {
    let mut dm = DomainMatcher::default();
    for d in list {
        let d = d.trim();
        if d.is_empty() || d.starts_with('#') {
            continue;
        }
        if let Some(code) = d.strip_prefix("geosite:") {
            let (code, attr) = match code.split_once('@') {
                Some((c, a)) => (c.to_ascii_lowercase(), Some(a.to_ascii_lowercase())),
                None => (code.to_ascii_lowercase(), None),
            };
            if let Some(list) = sites.get(&code) {
                for gd in list {
                    if let Some(a) = &attr {
                        if !gd.attrs.contains(a) {
                            continue;
                        }
                    }
                    dm.add(gd.kind, &gd.value);
                }
            }
        } else if let Some(v) = d.strip_prefix("domain:") {
            dm.add(2, v);
        } else if let Some(v) = d.strip_prefix("full:") {
            dm.add(3, v);
        } else if let Some(v) = d.strip_prefix("keyword:") {
            dm.add(0, v);
        } else if let Some(v) = d.strip_prefix("regexp:") {
            dm.add(1, v);
        } else if let Some(v) = d.strip_prefix("dotless:") {
            dm.add(1, &format!("^[^.]*{}[^.]*$", regex::escape(v)));
        } else {
            dm.add(0, d);
        }
    }
    dm
}

/// Коды geosite, упомянутые в списке доменных условий.
fn geosite_codes<'a>(list: impl IntoIterator<Item = &'a String>, out: &mut HashSet<String>) {
    for d in list {
        if let Some(c) = d.trim().strip_prefix("geosite:") {
            out.insert(c.split('@').next().unwrap_or("").to_ascii_lowercase());
        }
    }
}

/// Набор доменных условий одного маршрута на отдельный сервер.
pub struct DomainSet(DomainMatcher);

impl DomainSet {
    pub fn matches(&self, domain: &str) -> bool {
        self.0.matches(domain)
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Компилирует несколько списков доменов разом (geosite.dat читается один раз).
pub fn compile_domain_sets(lists: &[&[String]], geo_dir: &Path) -> Vec<DomainSet> {
    let mut codes = HashSet::new();
    for l in lists {
        geosite_codes(l.iter(), &mut codes);
    }
    let sites = if codes.is_empty() { HashMap::new() } else { geo::load_geosite(&geo_dir.join("geosite.dat"), &codes) };
    for c in &codes {
        if !sites.contains_key(c) {
            log::warn!("geosite:{c} не найден (скачайте geo-файлы в разделе «Маршруты»)");
        }
    }
    lists.iter().map(|l| DomainSet(compile_domains(l, &sites))).collect()
}

struct CompiledRule {
    tag: OutboundTag,
    name: String,
    domains: DomainMatcher,
    ips: IpMatcher,
    want_domain: bool,
    want_ip: bool,
    ports: Vec<(u16, u16)>,
    network: Option<Network>,
    protocols: Vec<String>,
}

/// Метаданные соединения для маршрутизации.
#[derive(Debug, Clone)]
pub struct Meta<'a> {
    pub domain: Option<&'a str>,
    pub ip: Option<IpAddr>,
    pub port: u16,
    pub network: Network,
    pub protocol: Option<&'a str>,
}

pub enum Decision {
    Tag(OutboundTag, String),
    /// Нужно разрешить домен и повторить с IP
    NeedIp,
}

pub struct Router {
    rules: Vec<CompiledRule>,
    pub final_tag: OutboundTag,
    pub strategy: String,
    pub has_ip_rules: bool,
}

fn parse_ports(s: &str) -> Vec<(u16, u16)> {
    let mut v = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((a, b)) = part.split_once('-') {
            if let (Ok(a), Ok(b)) = (a.trim().parse(), b.trim().parse()) {
                v.push((a, b));
            }
        } else if let Ok(p) = part.parse() {
            v.push((p, p));
        }
    }
    v
}

impl Router {
    /// Компилирует правила; geo-файлы ищутся в `geo_dir`.
    pub fn new(cfg: &RoutingConfig, geo_dir: &Path) -> Router {
        let enabled: Vec<&RoutingRule> = cfg.rules.iter().filter(|r| r.enabled).collect();
        // какие geo-коды нужны
        let mut site_codes = HashSet::new();
        let mut ip_codes = HashSet::new();
        for r in &enabled {
            geosite_codes(&r.domain, &mut site_codes);
            for i in &r.ip {
                if let Some(c) = i.trim().trim_start_matches('!').strip_prefix("geoip:") {
                    let c = c.trim_start_matches('!').to_ascii_lowercase();
                    if c != "private" {
                        ip_codes.insert(c);
                    }
                }
            }
        }
        let geosite_path: PathBuf = geo_dir.join("geosite.dat");
        let geoip_path: PathBuf = geo_dir.join("geoip.dat");
        let sites = if site_codes.is_empty() { HashMap::new() } else { geo::load_geosite(&geosite_path, &site_codes) };
        let geoips = if ip_codes.is_empty() { HashMap::new() } else { geo::load_geoip(&geoip_path, &ip_codes) };
        for c in &site_codes {
            if !sites.contains_key(c) {
                log::warn!("geosite:{c} не найден (скачайте geo-файлы в разделе «Маршруты»)");
            }
        }
        for c in &ip_codes {
            if !geoips.contains_key(c) {
                log::warn!("geoip:{c} не найден (скачайте geo-файлы в разделе «Маршруты»)");
            }
        }

        let mut rules = Vec::new();
        let mut has_ip_rules = false;
        for r in enabled {
            let dm = compile_domains(&r.domain, &sites);
            let mut im = IpMatcher::default();
            for i in &r.ip {
                let i = i.trim();
                if i.is_empty() || i.starts_with('#') {
                    continue;
                }
                let (neg, body) = match i.strip_prefix('!') {
                    Some(b) => (true, b),
                    None => (false, i),
                };
                if let Some(code) = body.strip_prefix("geoip:") {
                    let (neg, code) = match code.strip_prefix('!') {
                        Some(c) => (!neg, c),
                        None => (neg, code),
                    };
                    let code = code.to_ascii_lowercase();
                    if code == "private" {
                        for c in PRIVATE_CIDRS {
                            let (ip, p) = parse_cidr(c).unwrap();
                            im.add(ip, p, neg);
                        }
                    } else if let Some(g) = geoips.get(&code) {
                        for (ip, p) in &g.cidrs {
                            im.add(*ip, *p, neg ^ g.reverse);
                        }
                    }
                } else if let Some((ip, p)) = parse_cidr(body) {
                    im.add(ip, p, neg);
                } else {
                    log::warn!("неверный IP/CIDR в правиле: {i}");
                }
            }
            im.finish();
            let want_domain = r.domain.iter().any(|d| !d.trim().is_empty());
            let want_ip = r.ip.iter().any(|d| !d.trim().is_empty());
            if want_ip {
                has_ip_rules = true;
            }
            let network = match r.network.trim().to_lowercase().as_str() {
                "tcp" => Some(Network::Tcp),
                "udp" => Some(Network::Udp),
                _ => None,
            };
            rules.push(CompiledRule {
                tag: r.outbound,
                name: if r.remarks.is_empty() { r.summary() } else { r.remarks.clone() },
                domains: dm,
                ips: im,
                want_domain,
                want_ip,
                ports: parse_ports(&r.port),
                network,
                protocols: r.protocol.iter().map(|s| s.trim().to_lowercase()).filter(|s| !s.is_empty()).collect(),
            });
        }
        Router { rules, final_tag: cfg.final_outbound, strategy: cfg.domain_strategy.clone(), has_ip_rules }
    }

    fn rule_matches(r: &CompiledRule, m: &Meta) -> Option<bool> {
        if let Some(n) = r.network {
            if n != m.network {
                return Some(false);
            }
        }
        if !r.ports.is_empty() && !r.ports.iter().any(|(a, b)| m.port >= *a && m.port <= *b) {
            return Some(false);
        }
        if !r.protocols.is_empty() {
            match m.protocol {
                Some(p) if r.protocols.iter().any(|x| x == p) => {}
                _ => return Some(false),
            }
        }
        if r.want_domain {
            if r.domains.is_empty() {
                return Some(false);
            }
            match m.domain {
                Some(d) if r.domains.matches(d) => {}
                _ => return Some(false),
            }
        }
        if r.want_ip {
            if r.ips.is_empty() {
                return Some(false);
            }
            match m.ip {
                Some(ip) => {
                    if !r.ips.matches(ip) {
                        return Some(false);
                    }
                }
                None => return None, // IP неизвестен
            }
        }
        Some(true)
    }

    /// Маршрутизация. Если по стратегии нужен IP домена — возвращает NeedIp.
    pub fn route(&self, m: &Meta) -> Decision {
        let mut ip_unknown = false;
        for r in &self.rules {
            match Self::rule_matches(r, m) {
                Some(true) => return Decision::Tag(r.tag, r.name.clone()),
                Some(false) => {}
                None => {
                    ip_unknown = true;
                    if self.strategy == "IPOnDemand" && m.domain.is_some() {
                        return Decision::NeedIp;
                    }
                }
            }
        }
        if ip_unknown && self.strategy == "IPIfNonMatch" && m.domain.is_some() {
            return Decision::NeedIp;
        }
        Decision::Tag(self.final_tag, "по умолчанию".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RoutingRule;

    fn rule(tag: OutboundTag, domain: &[&str], ip: &[&str]) -> RoutingRule {
        RoutingRule {
            id: "x".into(),
            enabled: true,
            outbound: tag,
            domain: domain.iter().map(|s| s.to_string()).collect(),
            ip: ip.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    fn tag_of(d: Decision) -> Option<OutboundTag> {
        match d {
            Decision::Tag(t, _) => Some(t),
            Decision::NeedIp => None,
        }
    }

    #[test]
    fn domain_and_ip_rules() {
        let cfg = RoutingConfig {
            domain_strategy: "IPIfNonMatch".into(),
            rules: vec![
                rule(OutboundTag::Block, &["keyword:ads", "full:tracker.com"], &[]),
                rule(OutboundTag::Direct, &["domain:ru", "regexp:^.*\\.yandex\\.net$"], &[]),
                rule(OutboundTag::Direct, &[], &["geoip:private", "77.88.0.0/18"]),
            ],
            final_outbound: OutboundTag::Proxy,
            ..Default::default()
        };
        let r = Router::new(&cfg, Path::new("/nonexistent"));
        let m = |d: Option<&'static str>, ip: Option<&str>| Meta {
            domain: d,
            ip: ip.map(|s| s.parse().unwrap()),
            port: 443,
            network: Network::Tcp,
            protocol: None,
        };
        assert_eq!(tag_of(r.route(&m(Some("mail.ru"), None))), Some(OutboundTag::Direct));
        assert_eq!(tag_of(r.route(&m(Some("x.ads.com"), None))), Some(OutboundTag::Block));
        assert_eq!(tag_of(r.route(&m(Some("tracker.com"), None))), Some(OutboundTag::Block));
        assert_eq!(tag_of(r.route(&m(Some("sub.tracker.com"), None))), None); // NeedIp
        assert_eq!(tag_of(r.route(&m(Some("a.yandex.net"), None))), Some(OutboundTag::Direct));
        assert_eq!(tag_of(r.route(&m(None, Some("192.168.1.5")))), Some(OutboundTag::Direct));
        assert_eq!(tag_of(r.route(&m(None, Some("77.88.8.8")))), Some(OutboundTag::Direct));
        assert_eq!(tag_of(r.route(&m(None, Some("8.8.8.8")))), Some(OutboundTag::Proxy));
        assert_eq!(tag_of(r.route(&m(Some("google.com"), Some("8.8.8.8")))), Some(OutboundTag::Proxy));
    }
}
