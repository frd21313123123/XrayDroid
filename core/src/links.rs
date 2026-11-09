//! Разбор и генерация ссылок: vless://, vmess://, trojan://, ss://, socks://

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use percent_encoding::{percent_decode_str, utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use std::collections::HashMap;

use crate::config::{Profile, Protocol};

const ENC: &AsciiSet = &NON_ALPHANUMERIC.remove(b'-').remove(b'_').remove(b'.').remove(b'~');

pub fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let s: String = s.trim().chars().filter(|c| !c.is_whitespace()).collect();
    for e in [&STANDARD, &URL_SAFE, &STANDARD_NO_PAD, &URL_SAFE_NO_PAD] {
        if let Ok(v) = e.decode(&s) {
            return Some(v);
        }
    }
    let t = s.trim_end_matches('=');
    STANDARD_NO_PAD.decode(t).or_else(|_| URL_SAFE_NO_PAD.decode(t)).ok()
}

fn pct(s: &str) -> String {
    percent_decode_str(s).decode_utf8_lossy().into_owned()
}

fn enc(s: &str) -> String {
    utf8_percent_encode(s, ENC).to_string()
}

struct Url {
    user: String,
    host: String,
    port: u16,
    query: HashMap<String, String>,
    fragment: String,
}

fn parse_url(rest: &str) -> Option<Url> {
    let (rest, fragment) = match rest.split_once('#') {
        Some((a, b)) => (a, pct(b)),
        None => (rest, String::new()),
    };
    let (rest, query_s) = match rest.split_once('?') {
        Some((a, b)) => (a, b),
        None => (rest, ""),
    };
    let rest = rest.trim_end_matches('/');
    let (user, hostport) = match rest.rsplit_once('@') {
        Some((u, h)) => (u.to_string(), h),
        None => (String::new(), rest),
    };
    let (host, port) = parse_hostport(hostport)?;
    let mut query = HashMap::new();
    for kv in query_s.split('&') {
        if kv.is_empty() {
            continue;
        }
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        query.insert(k.to_string(), pct(v));
    }
    Some(Url { user, host, port, query, fragment })
}

fn parse_hostport(s: &str) -> Option<(String, u16)> {
    if let Some(r) = s.strip_prefix('[') {
        let (h, p) = r.split_once("]:")?;
        return Some((h.to_string(), p.trim_end_matches('/').parse().ok()?));
    }
    let (h, p) = s.rsplit_once(':')?;
    let p = p.trim_end_matches('/');
    let first = p.split([',', '-']).next().unwrap_or(p);
    Some((h.to_string(), first.parse().ok()?))
}

fn fmt_host(h: &str) -> String {
    if h.contains(':') {
        format!("[{h}]")
    } else {
        h.to_string()
    }
}

fn apply_stream_query(p: &mut Profile, q: &HashMap<String, String>) {
    let g = |k: &str| q.get(k).cloned().unwrap_or_default();
    p.network = q.get("type").cloned().unwrap_or_else(|| "tcp".into());
    if p.network == "splithttp" {
        p.network = "xhttp".into();
    }
    p.header_type = if p.network == "grpc" || p.network == "xhttp" { g("mode") } else { g("headerType") };
    p.host = g("host");
    p.path = if p.network == "grpc" { g("serviceName") } else { g("path") };
    p.security = q.get("security").cloned().unwrap_or_else(|| "none".into());
    p.sni = q.get("sni").or_else(|| q.get("peer")).cloned().unwrap_or_default();
    p.alpn = g("alpn");
    p.fingerprint = g("fp");
    p.public_key = g("pbk");
    p.short_id = g("sid");
    p.spider_x = g("spx");
    p.flow = g("flow");
    p.allow_insecure = matches!(q.get("allowInsecure").map(|s| s.as_str()), Some("1") | Some("true"))
        || matches!(q.get("insecure").map(|s| s.as_str()), Some("1") | Some("true"));
}

fn stream_query(p: &Profile) -> Vec<(String, String)> {
    let mut v: Vec<(String, String)> = Vec::new();
    let net = if p.network.is_empty() { "tcp" } else { &p.network };
    v.push(("type".into(), net.into()));
    let sec = if p.security.is_empty() { "none" } else { &p.security };
    v.push(("security".into(), sec.into()));
    let mut push = |k: &str, val: &str| {
        if !val.is_empty() {
            v.push((k.into(), val.into()));
        }
    };
    push("flow", &p.flow);
    if net == "grpc" || net == "xhttp" {
        push("mode", &p.header_type);
    } else {
        push("headerType", &p.header_type);
    }
    push("host", &p.host);
    if net == "grpc" {
        push("serviceName", &p.path);
    } else {
        push("path", &p.path);
    }
    push("sni", &p.sni);
    push("alpn", &p.alpn);
    push("fp", &p.fingerprint);
    push("pbk", &p.public_key);
    push("sid", &p.short_id);
    push("spx", &p.spider_x);
    if p.allow_insecure {
        v.push(("allowInsecure".into(), "1".into()));
    }
    v
}

fn join_query(v: &[(String, String)]) -> String {
    v.iter().map(|(k, val)| format!("{}={}", k, enc(val))).collect::<Vec<_>>().join("&")
}

/// Разбор одной ссылки.
pub fn parse_link(line: &str) -> Option<Profile> {
    let line = line.trim();
    let (scheme, rest) = line.split_once("://")?;
    let mut p = Profile { id: Profile::new_id(), ..Default::default() };
    match scheme.to_ascii_lowercase().as_str() {
        "vless" => {
            let u = parse_url(rest)?;
            p.protocol = Protocol::Vless;
            p.id_or_password = pct(&u.user);
            p.address = u.host;
            p.port = u.port;
            p.method = u.query.get("encryption").cloned().unwrap_or_else(|| "none".into());
            apply_stream_query(&mut p, &u.query);
            p.remarks = u.fragment;
        }
        "trojan" => {
            let u = parse_url(rest)?;
            p.protocol = Protocol::Trojan;
            p.id_or_password = pct(&u.user);
            p.address = u.host;
            p.port = u.port;
            apply_stream_query(&mut p, &u.query);
            if !u.query.contains_key("security") {
                p.security = "tls".into();
            }
            p.remarks = u.fragment;
        }
        "vmess" => {
            let (body, frag) = rest.split_once('#').unwrap_or((rest, ""));
            if let Some(js) = b64_decode(body).and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok()) {
                let s = |k: &str| -> String {
                    match js.get(k) {
                        Some(serde_json::Value::String(s)) => s.clone(),
                        Some(serde_json::Value::Number(n)) => n.to_string(),
                        _ => String::new(),
                    }
                };
                p.protocol = Protocol::Vmess;
                p.remarks = s("ps");
                p.address = s("add");
                p.port = s("port").parse().ok()?;
                p.id_or_password = s("id");
                p.method = if s("scy").is_empty() { "auto".into() } else { s("scy") };
                p.network = if s("net").is_empty() { "tcp".into() } else { s("net") };
                p.header_type = s("type");
                p.host = s("host");
                p.path = s("path");
                p.security = if s("tls").is_empty() { "none".into() } else { s("tls") };
                p.sni = s("sni");
                p.alpn = s("alpn");
                p.fingerprint = s("fp");
                if p.remarks.is_empty() && !frag.is_empty() {
                    p.remarks = pct(frag);
                }
            } else {
                // Формат vmess://uuid@host:port?... (стандарт VMessAEAD/ducksoft)
                let u = parse_url(rest)?;
                p.protocol = Protocol::Vmess;
                p.id_or_password = pct(&u.user);
                p.address = u.host;
                p.port = u.port;
                p.method = u.query.get("encryption").cloned().unwrap_or_else(|| "auto".into());
                apply_stream_query(&mut p, &u.query);
                p.remarks = u.fragment;
            }
        }
        "ss" => {
            p.protocol = Protocol::Shadowsocks;
            let (body, frag) = rest.split_once('#').map(|(a, b)| (a, pct(b))).unwrap_or((rest, String::new()));
            p.remarks = frag;
            let body = body.split('?').next().unwrap_or(body).trim_end_matches('/');
            if let Some((userinfo, hostport)) = body.rsplit_once('@') {
                let ui = pct(userinfo);
                let decoded = if ui.contains(':') {
                    ui
                } else {
                    String::from_utf8(b64_decode(&ui)?).ok()?
                };
                let (m, pw) = decoded.split_once(':')?;
                p.method = m.to_string();
                p.id_or_password = pw.to_string();
                let (h, port) = parse_hostport(hostport)?;
                p.address = h;
                p.port = port;
            } else {
                // ss://base64(method:password@host:port)
                let decoded = String::from_utf8(b64_decode(body)?).ok()?;
                let (mp, hp) = decoded.rsplit_once('@')?;
                let (m, pw) = mp.split_once(':')?;
                p.method = m.into();
                p.id_or_password = pw.into();
                let (h, port) = parse_hostport(hp)?;
                p.address = h;
                p.port = port;
            }
        }
        "hysteria2" | "hy2" => {
            let u = parse_url(rest)?;
            let g = |k: &str| u.query.get(k).cloned().unwrap_or_default();
            p.protocol = Protocol::Hysteria2;
            p.id_or_password = pct(&u.user);
            p.address = u.host;
            p.port = u.port;
            p.sni = g("sni");
            p.allow_insecure = matches!(g("insecure").as_str(), "1" | "true");
            p.obfs = g("obfs");
            p.obfs_password = g("obfs-password");
            p.security = "tls".into();
            p.remarks = u.fragment;
        }
        "tuic" => {
            let u = parse_url(rest)?;
            let g = |k: &str| u.query.get(k).cloned().unwrap_or_default();
            p.protocol = Protocol::Tuic;
            let user = pct(&u.user);
            let (id, pw) = user.split_once(':').unwrap_or((&user, ""));
            p.id_or_password = id.to_string();
            p.secret = pw.to_string();
            p.address = u.host;
            p.port = u.port;
            p.sni = g("sni");
            p.alpn = g("alpn");
            p.allow_insecure = matches!(g("allow_insecure").as_str(), "1" | "true") || matches!(g("insecure").as_str(), "1" | "true");
            p.security = "tls".into();
            p.remarks = u.fragment;
        }
        "anytls" => {
            let u = parse_url(rest)?;
            let g = |k: &str| u.query.get(k).cloned().unwrap_or_default();
            p.protocol = Protocol::AnyTls;
            p.id_or_password = pct(&u.user);
            p.address = u.host;
            p.port = u.port;
            p.sni = g("sni");
            p.allow_insecure = matches!(g("insecure").as_str(), "1" | "true") || matches!(g("allowInsecure").as_str(), "1" | "true");
            p.security = "tls".into();
            p.remarks = u.fragment;
        }
        "http" | "https" => {
            // только вида scheme://[user:pass@]host:port[/]#имя — ссылки с путём это подписки
            let (body, _) = rest.split_once('#')?;
            if body.trim_end_matches('/').contains('/') || body.contains('?') {
                return None;
            }
            let u = parse_url(rest)?;
            p.protocol = Protocol::Http;
            p.address = u.host;
            p.port = u.port;
            p.remarks = u.fragment;
            p.security = if scheme.eq_ignore_ascii_case("https") { "tls".into() } else { "none".into() };
            if !u.user.is_empty() {
                let (a, b) = u.user.split_once(':').unwrap_or((&u.user, ""));
                p.username = pct(a);
                p.id_or_password = pct(b);
            }
        }
        "socks" | "socks5" => {
            let u = parse_url(rest)?;
            p.protocol = Protocol::Socks;
            p.address = u.host;
            p.port = u.port;
            p.remarks = u.fragment;
            if !u.user.is_empty() {
                let ui = pct(&u.user);
                let dec = if ui.contains(':') { ui } else { String::from_utf8(b64_decode(&ui)?).ok()? };
                let (a, b) = dec.split_once(':').unwrap_or((&dec, ""));
                p.username = a.into();
                p.id_or_password = b.into();
            }
        }
        _ => return None,
    }
    if p.address.is_empty() || p.port == 0 {
        return None;
    }
    Some(p)
}

/// Разбор текста с несколькими ссылками (или base64-подписки).
pub fn parse_many(text: &str) -> Vec<Profile> {
    let text = text.trim();
    let mut out: Vec<Profile> = text.lines().filter_map(parse_link).collect();
    if out.is_empty() {
        if let Some(dec) = b64_decode(text) {
            let s = String::from_utf8_lossy(&dec);
            out = s.lines().filter_map(parse_link).collect();
        }
    }
    out
}

/// Генерация ссылки для обмена.
pub fn to_link(p: &Profile) -> String {
    let frag = enc(&p.remarks);
    let host = fmt_host(&p.address);
    match p.protocol {
        Protocol::Vless => {
            let mut q = stream_query(p);
            q.insert(0, ("encryption".into(), if p.method.is_empty() { "none".into() } else { p.method.clone() }));
            format!("vless://{}@{}:{}?{}#{}", enc(&p.id_or_password), host, p.port, join_query(&q), frag)
        }
        Protocol::Trojan => {
            format!("trojan://{}@{}:{}?{}#{}", enc(&p.id_or_password), host, p.port, join_query(&stream_query(p)), frag)
        }
        Protocol::Vmess => {
            let js = serde_json::json!({
                "v": "2", "ps": p.remarks, "add": p.address, "port": p.port.to_string(),
                "id": p.id_or_password, "aid": "0", "scy": if p.method.is_empty() { "auto" } else { &p.method },
                "net": if p.network.is_empty() { "tcp" } else { &p.network }, "type": if p.header_type.is_empty() { "none" } else { &p.header_type },
                "host": p.host, "path": p.path,
                "tls": if p.security == "none" { "" } else { &p.security },
                "sni": p.sni, "alpn": p.alpn, "fp": p.fingerprint,
            });
            format!("vmess://{}", STANDARD.encode(js.to_string()))
        }
        Protocol::Shadowsocks => {
            let ui = URL_SAFE_NO_PAD.encode(format!("{}:{}", p.method, p.id_or_password));
            format!("ss://{}@{}:{}#{}", ui, host, p.port, frag)
        }
        Protocol::Hysteria2 => {
            let mut q: Vec<(String, String)> = Vec::new();
            if !p.sni.is_empty() {
                q.push(("sni".into(), p.sni.clone()));
            }
            if p.allow_insecure {
                q.push(("insecure".into(), "1".into()));
            }
            if !p.obfs.is_empty() {
                q.push(("obfs".into(), p.obfs.clone()));
                q.push(("obfs-password".into(), p.obfs_password.clone()));
            }
            format!("hysteria2://{}@{}:{}/?{}#{}", enc(&p.id_or_password), host, p.port, join_query(&q), frag)
        }
        Protocol::Tuic => {
            let mut q: Vec<(String, String)> = vec![("congestion_control".into(), "bbr".into()), ("udp_relay_mode".into(), "native".into())];
            if !p.sni.is_empty() {
                q.push(("sni".into(), p.sni.clone()));
            }
            if !p.alpn.is_empty() {
                q.push(("alpn".into(), p.alpn.clone()));
            }
            if p.allow_insecure {
                q.push(("allow_insecure".into(), "1".into()));
            }
            format!("tuic://{}:{}@{}:{}?{}#{}", enc(&p.id_or_password), enc(&p.secret), host, p.port, join_query(&q), frag)
        }
        Protocol::AnyTls => {
            let mut q: Vec<(String, String)> = Vec::new();
            if !p.sni.is_empty() {
                q.push(("sni".into(), p.sni.clone()));
            }
            if p.allow_insecure {
                q.push(("insecure".into(), "1".into()));
            }
            format!("anytls://{}@{}:{}?{}#{}", enc(&p.id_or_password), host, p.port, join_query(&q), frag)
        }
        Protocol::Http => {
            let scheme = if p.security == "tls" { "https" } else { "http" };
            if p.username.is_empty() && p.id_or_password.is_empty() {
                format!("{scheme}://{}:{}#{}", host, p.port, frag)
            } else {
                format!("{scheme}://{}:{}@{}:{}#{}", enc(&p.username), enc(&p.id_or_password), host, p.port, frag)
            }
        }
        Protocol::Socks => {
            if p.username.is_empty() {
                format!("socks://{}:{}#{}", host, p.port, frag)
            } else {
                let ui = STANDARD.encode(format!("{}:{}", p.username, p.id_or_password));
                format!("socks://{}@{}:{}#{}", enc(&ui), host, p.port, frag)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vless_reality() {
        let l = "vless://0a6b0b6f-9e4c-4d0c-9f3a-1f2e3d4c5b6a@1.2.3.4:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=Y8dqSZ0mhh1sV-hcQSbPGI2xC5NUrq6rLDf2C_RXKCk&sid=6ba85179e30d4fc2&type=tcp&headerType=none#%D0%93%D0%B5%D1%80%D0%BC%D0%B0%D0%BD%D0%B8%D1%8F";
        let p = parse_link(l).unwrap();
        assert_eq!(p.protocol, Protocol::Vless);
        assert_eq!(p.port, 443);
        assert_eq!(p.security, "reality");
        assert_eq!(p.flow, "xtls-rprx-vision");
        assert_eq!(p.remarks, "Германия");
        let p2 = parse_link(&to_link(&p)).unwrap();
        assert_eq!(p2.public_key, p.public_key);
        assert_eq!(p2.remarks, p.remarks);
    }

    #[test]
    fn ss_variants() {
        let p = parse_link("ss://YWVzLTI1Ni1nY206cGFzcw@example.com:8388#test").unwrap();
        assert_eq!(p.method, "aes-256-gcm");
        assert_eq!(p.id_or_password, "pass");
        let p = parse_link("ss://YWVzLTEyOC1nY206dGVzdEAxOTIuMTY4LjEuMTo4ODg4#x").unwrap();
        assert_eq!(p.address, "192.168.1.1");
        assert_eq!(p.port, 8888);
        let p = parse_link("ss://2022-blake3-aes-128-gcm:abc%3D@[::1]:80#y").unwrap();
        assert_eq!(p.id_or_password, "abc=");
        assert_eq!(p.address, "::1");
    }

    #[test]
    fn quic_links() {
        let p = parse_link("hy2://pa%40ss@example.com:443,20000-30000/?sni=a.com&insecure=1&obfs=salamander&obfs-password=xx#h").unwrap();
        assert_eq!(p.protocol, Protocol::Hysteria2);
        assert_eq!(p.port, 443);
        assert_eq!(p.id_or_password, "pa@ss");
        assert_eq!(p.obfs_password, "xx");
        let p2 = parse_link(&to_link(&p)).unwrap();
        assert_eq!(p2.obfs, "salamander");
        let t = parse_link("tuic://0a6b0b6f-9e4c-4d0c-9f3a-1f2e3d4c5b6a:secret@1.2.3.4:443?alpn=h3&sni=x.com#t").unwrap();
        assert_eq!(t.secret, "secret");
        assert_eq!(parse_link(&to_link(&t)).unwrap().secret, "secret");
        let a = parse_link("anytls://pw@a.com:443?sni=b.com#a").unwrap();
        assert_eq!(a.protocol, Protocol::AnyTls);
    }

    #[test]
    fn vmess_json() {
        let js = r#"{"v":"2","ps":"vm","add":"a.com","port":"443","id":"b831381d-6324-4d53-ad4f-8cda48b30811","aid":"0","net":"ws","type":"none","host":"a.com","path":"/ws","tls":"tls"}"#;
        let l = format!("vmess://{}", STANDARD.encode(js));
        let p = parse_link(&l).unwrap();
        assert_eq!(p.network, "ws");
        assert_eq!(p.security, "tls");
        assert_eq!(p.path, "/ws");
    }
}
