//! Готовые наборы правил маршрутизации.

use crate::config::{OutboundTag, RoutingConfig, RoutingRule};

pub const DEFAULT_PRESET: &str = "ru_bypass";

pub const PRESETS: &[(&str, &str)] = &[
    ("ru_bypass", "Россия напрямую, остальное через прокси"),
    ("ru_blocked", "Через прокси только заблокированное в РФ"),
    ("bypass_lan", "Обход локальной сети"),
    ("global", "Всё через прокси"),
    ("direct", "Всё напрямую"),
];

const BLOCKED_FALLBACK: &[&str] = &[
    "domain:youtube.com", "domain:youtu.be", "domain:googlevideo.com", "domain:ytimg.com", "domain:ggpht.com",
    "domain:youtubei.googleapis.com", "domain:instagram.com", "domain:cdninstagram.com", "domain:facebook.com",
    "domain:fbcdn.net", "domain:whatsapp.com", "domain:whatsapp.net", "domain:discord.com", "domain:discord.gg",
    "domain:discordapp.com", "domain:discordapp.net", "domain:discord.media", "domain:x.com", "domain:twitter.com",
    "domain:twimg.com", "domain:t.co", "domain:linkedin.com", "domain:licdn.com", "domain:telegram.org", "domain:t.me",
    "domain:telegram.me", "domain:chatgpt.com", "domain:openai.com", "domain:oaistatic.com", "domain:oaiusercontent.com",
    "domain:claude.ai", "domain:anthropic.com", "domain:soundcloud.com", "domain:spotify.com", "domain:medium.com",
    "domain:patreon.com", "domain:signal.org", "domain:viber.com", "domain:netflix.com", "domain:rutracker.org",
];

const RU_DIRECT: &[&str] = &[
    "geosite:category-ru", "domain:ru", "domain:su", "domain:xn--p1ai", "domain:xn--d1acj3b", "domain:yandex.net",
    "domain:yandex.com", "domain:yastatic.net", "domain:vk.com", "domain:userapi.com", "domain:vk.me", "domain:vkuser.net",
    "domain:mycdn.me", "domain:ok.ru", "domain:gosuslugi.ru", "domain:sberbank.com", "domain:tinkoff.ru",
    "domain:tbank.ru", "domain:ozon.ru", "domain:wildberries.ru", "domain:wb.ru", "domain:avito.st", "domain:rutube.ru",
    "domain:kinopoisk.ru", "domain:max.ru", "domain:2gis.com",
];

fn rule(remarks: &str, tag: OutboundTag, domain: &[&str], ip: &[&str], enabled: bool) -> RoutingRule {
    RoutingRule {
        id: crate::config::Profile::new_id(),
        remarks: remarks.into(),
        enabled,
        outbound: tag,
        domain: domain.iter().map(|s| s.to_string()).collect(),
        ip: ip.iter().map(|s| s.to_string()).collect(),
        ..Default::default()
    }
}

pub fn apply_preset(cfg: &mut RoutingConfig, name: &str) {
    let ads = rule("Блокировка рекламы", OutboundTag::Block, &["geosite:category-ads-all"], &[], false);
    let lan = rule("Локальная сеть напрямую", OutboundTag::Direct, &["domain:local", "domain:lan"], &["geoip:private"], true);
    let (rules, fin) = match name {
        "ru_bypass" => (
            vec![
                ads,
                lan,
                rule("Заблокированное в РФ — через прокси", OutboundTag::Proxy, &["geosite:ru-blocked"], &[], true),
                rule("Российские сайты напрямую", OutboundTag::Direct, RU_DIRECT, &[], true),
                rule("Российские IP напрямую", OutboundTag::Direct, &[], &["geoip:ru"], true),
            ],
            OutboundTag::Proxy,
        ),
        "ru_blocked" => {
            let mut domains = vec!["geosite:ru-blocked"];
            domains.extend_from_slice(BLOCKED_FALLBACK);
            (
                vec![
                    ads,
                    lan,
                    rule("Заблокированные сайты — через прокси", OutboundTag::Proxy, &domains, &[], true),
                    rule("Заблокированные IP — через прокси", OutboundTag::Proxy, &[], &["geoip:ru-blocked"], true),
                ],
                OutboundTag::Direct,
            )
        }
        "bypass_lan" => (vec![ads, lan], OutboundTag::Proxy),
        "direct" => (vec![], OutboundTag::Direct),
        _ => (vec![], OutboundTag::Proxy),
    };
    cfg.rules = rules;
    cfg.final_outbound = fin;
    cfg.preset = name.to_string();
}
