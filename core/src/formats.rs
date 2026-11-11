//! Импорт серверов не из ссылок: Clash / Mihomo (YAML), sing-box и Xray (JSON), SIP008.
//! Подписки и буфер обмена разбираются одной функцией — [`parse_any`].

use serde_json::Value;

use crate::config::{Profile, Protocol};
use crate::links::{self, normalize_network};

// ───────────────────────── доступ к полям ─────────────────────────

/// Строка, число или булево значение поля — строкой.
fn s(v: &Value, k: &str) -> String {
    match v.get(k) {
        Some(Value::String(x)) => x.trim().to_string(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::Bool(b)) => b.to_string(),
        _ => String::new(),
    }
}

fn first(v: &Value, keys: &[&str]) -> String {
    keys.iter().map(|k| s(v, k)).find(|x| !x.is_empty()).unwrap_or_default()
}

fn truthy(v: &Value, k: &str) -> bool {
    match v.get(k) {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(x)) => matches!(x.as_str(), "true" | "1"),
        Some(Value::Number(n)) => n.as_i64() == Some(1),
        _ => false,
    }
}

/// Массив строк/чисел → "a,b"; строка → как есть.
fn list(v: &Value, k: &str) -> String {
    match v.get(k) {
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(|x| match x {
                Value::String(s) => Some(s.trim().to_string()),
                Value::Number(n) => Some(n.to_string()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join(","),
        Some(_) => s(v, k),
        None => String::new(),
    }
}

fn port(v: &Value, k: &str) -> u16 {
    s(v, k).parse().unwrap_or(0)
}

fn obj<'a>(v: &'a Value, k: &str) -> &'a Value {
    static NULL: Value = Value::Null;
    v.get(k).unwrap_or(&NULL)
}

/// Заголовок Host из объекта headers (значение — строка или массив).
fn host_header(headers: &Value) -> String {
    for k in ["Host", "host"] {
        let h = list(headers, k);
        if !h.is_empty() {
            return h.split(',').next().unwrap_or("").to_string();
        }
    }
    String::new()
}

/// Ранние данные WebSocket записываются в путь, как в ссылках Xray: `/ws?ed=2048`.
fn with_early_data(path: String, max: &str, header: &str) -> String {
    let n: u32 = max.parse().unwrap_or(0);
    if n == 0 || path.contains("ed=") || !(header.is_empty() || header.eq_ignore_ascii_case("Sec-WebSocket-Protocol")) {
        return path;
    }
    let path = if path.is_empty() { "/".to_string() } else { path };
    format!("{path}{}ed={n}", if path.contains('?') { '&' } else { '?' })
}

/// Проверка и приведение профиля к принятому в приложении виду.
fn finish(mut p: Profile) -> Option<Profile> {
    p.address = p.address.trim().trim_start_matches('[').trim_end_matches(']').to_string();
    if p.address.is_empty() || p.port == 0 {
        return None;
    }
    p.network = normalize_network(&p.network);
    if p.security.is_empty() {
        p.security = if p.protocol.always_tls() { "tls".into() } else { "none".into() };
    }
    match p.protocol {
        Protocol::Vless if p.method.is_empty() => p.method = "none".into(),
        Protocol::Vmess if p.method.is_empty() => p.method = "auto".into(),
        _ => {}
    }
    if p.id.is_empty() {
        p.id = Profile::new_id();
    }
    Some(p)
}

fn wg_reserved(v: &Value, k: &str) -> String {
    list(v, k)
}

// ───────────────────────── Clash / Mihomo ─────────────────────────

fn clash_stream(p: &mut Profile, v: &Value) {
    p.network = normalize_network(&s(v, "network"));
    if truthy(v, "tls") {
        p.security = "tls".into();
    }
    p.sni = first(v, &["servername", "sni"]);
    p.allow_insecure = truthy(v, "skip-cert-verify");
    p.alpn = list(v, "alpn");
    p.fingerprint = s(v, "client-fingerprint");
    let reality = obj(v, "reality-opts");
    if reality.is_object() {
        p.security = "reality".into();
        p.public_key = s(reality, "public-key");
        p.short_id = s(reality, "short-id");
    }
    match p.network.as_str() {
        "ws" => {
            let o = obj(v, "ws-opts");
            p.host = host_header(obj(o, "headers"));
            p.path = with_early_data(s(o, "path"), &s(o, "max-early-data"), &s(o, "early-data-header-name"));
            if truthy(o, "v2ray-http-upgrade") {
                p.network = "httpupgrade".into();
            }
        }
        "grpc" => p.path = s(obj(v, "grpc-opts"), "grpc-service-name"),
        "http" => {
            // TCP с HTTP-маскировкой
            let o = obj(v, "http-opts");
            p.network = "tcp".into();
            p.header_type = "http".into();
            p.path = list(o, "path");
            p.host = host_header(obj(o, "headers"));
        }
        "h2" => {
            let o = obj(v, "h2-opts");
            p.host = list(o, "host");
            p.path = s(o, "path");
        }
        "xhttp" => {
            let o = obj(v, "xhttp-opts");
            p.host = s(o, "host");
            p.path = s(o, "path");
            p.header_type = s(o, "mode");
        }
        _ => {}
    }
}

fn clash_proxy(v: &Value) -> Option<Profile> {
    let mut p = Profile { remarks: s(v, "name"), address: s(v, "server"), port: port(v, "port"), ..Default::default() };
    match s(v, "type").to_ascii_lowercase().as_str() {
        "ss" | "shadowsocks" => {
            p.protocol = Protocol::Shadowsocks;
            p.method = s(v, "cipher");
            p.id_or_password = s(v, "password");
            let plugin = s(v, "plugin");
            if !plugin.is_empty() {
                let o = obj(v, "plugin-opts");
                // в Clash мультиплексирование v2ray-plugin включено, если не указано иное
                let mux = match o.get("mux") {
                    Some(Value::Bool(false)) => "0",
                    _ => "1",
                };
                let mut spec = format!("{plugin};mode={};host={};path={};mux={mux}", s(o, "mode"), s(o, "host"), s(o, "path"));
                if truthy(o, "tls") {
                    spec.push_str(";tls");
                }
                if !links::apply_ss_plugin(&mut p, &spec) {
                    return None;
                }
                if truthy(o, "skip-cert-verify") {
                    p.allow_insecure = true;
                }
            }
        }
        "vmess" => {
            p.protocol = Protocol::Vmess;
            p.id_or_password = s(v, "uuid");
            p.method = s(v, "cipher");
            clash_stream(&mut p, v);
        }
        "vless" => {
            p.protocol = Protocol::Vless;
            p.id_or_password = s(v, "uuid");
            p.flow = s(v, "flow");
            p.method = s(v, "encryption");
            clash_stream(&mut p, v);
        }
        "trojan" => {
            p.protocol = Protocol::Trojan;
            p.id_or_password = s(v, "password");
            clash_stream(&mut p, v);
            if p.security.is_empty() || p.security == "none" {
                p.security = "tls".into();
            }
        }
        "socks5" | "socks" => {
            p.protocol = Protocol::Socks;
            p.username = s(v, "username");
            p.id_or_password = s(v, "password");
        }
        "http" => {
            p.protocol = Protocol::Http;
            p.username = s(v, "username");
            p.id_or_password = s(v, "password");
            if truthy(v, "tls") {
                p.security = "tls".into();
                p.sni = s(v, "sni");
                p.allow_insecure = truthy(v, "skip-cert-verify");
            }
        }
        "hysteria2" | "hy2" => {
            p.protocol = Protocol::Hysteria2;
            p.id_or_password = first(v, &["password", "auth"]);
            p.ports = s(v, "ports");
            if p.port == 0 {
                p.port = crate::proxy::quic::parse_ports(&p.ports).first().copied().unwrap_or(0);
            }
            p.obfs = s(v, "obfs");
            p.obfs_password = s(v, "obfs-password");
            p.sni = s(v, "sni");
            p.alpn = list(v, "alpn");
            p.allow_insecure = truthy(v, "skip-cert-verify");
            // fingerprint в Clash — SHA-256 сертификата сервера
            p.pinned_cert_sha256 = s(v, "fingerprint");
        }
        "tuic" => {
            if !s(v, "token").is_empty() {
                return None; // TUIC v4
            }
            p.protocol = Protocol::Tuic;
            p.id_or_password = s(v, "uuid");
            p.secret = s(v, "password");
            p.congestion = match s(v, "congestion-controller").as_str() {
                "" | "bbr" => String::new(),
                c => c.to_string(),
            };
            p.udp_relay_mode = if s(v, "udp-relay-mode") == "quic" { "quic".into() } else { String::new() };
            p.sni = s(v, "sni");
            p.alpn = list(v, "alpn");
            p.allow_insecure = truthy(v, "skip-cert-verify");
        }
        "anytls" => {
            p.protocol = Protocol::AnyTls;
            p.id_or_password = s(v, "password");
            p.sni = s(v, "sni");
            p.alpn = list(v, "alpn");
            p.fingerprint = s(v, "client-fingerprint");
            p.allow_insecure = truthy(v, "skip-cert-verify");
        }
        "wireguard" => {
            p.protocol = Protocol::WireGuard;
            p.id_or_password = s(v, "private-key");
            // у Mihomo параметры узла могут лежать в peers[0]
            let peer = v.get("peers").and_then(|x| x.get(0)).unwrap_or(v);
            if p.address.is_empty() {
                p.address = s(peer, "server");
                p.port = port(peer, "port");
            }
            p.public_key = first(peer, &["public-key", "publickey"]);
            p.secret = first(peer, &["pre-shared-key", "preshared-key"]);
            p.reserved = if wg_reserved(peer, "reserved").is_empty() { wg_reserved(v, "reserved") } else { wg_reserved(peer, "reserved") };
            p.local_address = [s(v, "ip"), s(v, "ipv6")].into_iter().filter(|x| !x.is_empty()).collect::<Vec<_>>().join(",");
            p.mtu = s(v, "mtu").parse().unwrap_or(0);
        }
        _ => return None,
    }
    finish(p)
}

// ───────────────────────── sing-box ─────────────────────────

fn singbox_tls(p: &mut Profile, v: &Value) {
    let t = obj(v, "tls");
    if !t.is_object() || t.get("enabled") == Some(&Value::Bool(false)) {
        return;
    }
    p.security = "tls".into();
    p.sni = s(t, "server_name");
    p.allow_insecure = truthy(t, "insecure");
    p.alpn = list(t, "alpn");
    let utls = obj(t, "utls");
    if truthy(utls, "enabled") {
        p.fingerprint = s(utls, "fingerprint");
    }
    let r = obj(t, "reality");
    if truthy(r, "enabled") {
        p.security = "reality".into();
        p.public_key = s(r, "public_key");
        p.short_id = s(r, "short_id");
    }
}

fn singbox_transport(p: &mut Profile, v: &Value) {
    let t = obj(v, "transport");
    if !t.is_object() {
        return;
    }
    match s(t, "type").as_str() {
        "ws" => {
            p.network = "ws".into();
            p.host = host_header(obj(t, "headers"));
            p.path = with_early_data(s(t, "path"), &s(t, "max_early_data"), &s(t, "early_data_header_name"));
        }
        "grpc" => {
            p.network = "grpc".into();
            p.path = s(t, "service_name");
        }
        "httpupgrade" => {
            p.network = "httpupgrade".into();
            p.host = s(t, "host");
            p.path = s(t, "path");
        }
        "http" => {
            p.network = "h2".into();
            p.host = list(t, "host");
            p.path = s(t, "path");
        }
        other => p.network = other.to_string(),
    }
}

fn singbox_outbound(v: &Value) -> Option<Profile> {
    let mut p = Profile { remarks: s(v, "tag"), address: s(v, "server"), port: port(v, "server_port"), ..Default::default() };
    match s(v, "type").as_str() {
        "vless" => {
            p.protocol = Protocol::Vless;
            p.id_or_password = s(v, "uuid");
            p.flow = s(v, "flow");
            singbox_tls(&mut p, v);
            singbox_transport(&mut p, v);
        }
        "vmess" => {
            p.protocol = Protocol::Vmess;
            p.id_or_password = s(v, "uuid");
            p.method = s(v, "security");
            singbox_tls(&mut p, v);
            singbox_transport(&mut p, v);
        }
        "trojan" => {
            p.protocol = Protocol::Trojan;
            p.id_or_password = s(v, "password");
            singbox_tls(&mut p, v);
            singbox_transport(&mut p, v);
        }
        "shadowsocks" => {
            p.protocol = Protocol::Shadowsocks;
            p.method = s(v, "method");
            p.id_or_password = s(v, "password");
            let plugin = s(v, "plugin");
            if !plugin.is_empty() && !links::apply_ss_plugin(&mut p, &format!("{plugin};{}", s(v, "plugin_opts"))) {
                return None;
            }
        }
        "socks" => {
            if matches!(s(v, "version").as_str(), "4" | "4a") {
                return None;
            }
            p.protocol = Protocol::Socks;
            p.username = s(v, "username");
            p.id_or_password = s(v, "password");
        }
        "http" => {
            p.protocol = Protocol::Http;
            p.username = s(v, "username");
            p.id_or_password = s(v, "password");
            singbox_tls(&mut p, v);
        }
        "hysteria2" => {
            p.protocol = Protocol::Hysteria2;
            p.id_or_password = s(v, "password");
            let o = obj(v, "obfs");
            p.obfs = s(o, "type");
            p.obfs_password = s(o, "password");
            // "2080:3000" → "2080-3000"
            p.ports = list(v, "server_ports").replace(':', "-");
            if p.port == 0 {
                p.port = crate::proxy::quic::parse_ports(&p.ports).first().copied().unwrap_or(0);
            }
            singbox_tls(&mut p, v);
        }
        "tuic" => {
            p.protocol = Protocol::Tuic;
            p.id_or_password = s(v, "uuid");
            p.secret = s(v, "password");
            p.congestion = match s(v, "congestion_control").as_str() {
                "" | "bbr" => String::new(),
                c => c.to_string(),
            };
            p.udp_relay_mode = if s(v, "udp_relay_mode") == "quic" { "quic".into() } else { String::new() };
            singbox_tls(&mut p, v);
        }
        "anytls" => {
            p.protocol = Protocol::AnyTls;
            p.id_or_password = s(v, "password");
            singbox_tls(&mut p, v);
        }
        "naive" => {
            p.protocol = Protocol::Naive;
            p.username = s(v, "username");
            p.id_or_password = s(v, "password");
            singbox_tls(&mut p, v);
        }
        "wireguard" => {
            p.protocol = Protocol::WireGuard;
            p.id_or_password = s(v, "private_key");
            p.mtu = s(v, "mtu").parse().unwrap_or(0);
            match v.get("peers").and_then(|x| x.get(0)) {
                // endpoint (sing-box 1.11+): адреса интерфейса в address, узел — в peers
                Some(peer) => {
                    p.address = first(peer, &["address", "server"]);
                    p.port = s(peer, "port").parse().or_else(|_| s(peer, "server_port").parse()).unwrap_or(0);
                    p.public_key = s(peer, "public_key");
                    p.secret = s(peer, "pre_shared_key");
                    p.reserved = wg_reserved(peer, "reserved");
                    p.local_address = if list(v, "address").is_empty() { list(v, "local_address") } else { list(v, "address") };
                }
                None => {
                    p.public_key = s(v, "peer_public_key");
                    p.secret = s(v, "pre_shared_key");
                    p.reserved = wg_reserved(v, "reserved");
                    p.local_address = list(v, "local_address");
                }
            }
        }
        _ => return None,
    }
    finish(p)
}

// ───────────────────────── Xray / v2ray ─────────────────────────

fn xray_stream(p: &mut Profile, st: &Value) {
    if !st.is_object() {
        return;
    }
    p.network = normalize_network(&s(st, "network"));
    p.security = match s(st, "security").as_str() {
        "" => "none".into(),
        "xtls" => "tls".into(),
        x => x.to_string(),
    };
    let tls = obj(st, "tlsSettings");
    if p.security == "tls" && tls.is_object() {
        p.sni = s(tls, "serverName");
        p.alpn = list(tls, "alpn");
        p.fingerprint = s(tls, "fingerprint");
        p.allow_insecure = truthy(tls, "allowInsecure");
        p.pinned_cert_sha256 = first(tls, &["pinnedPeerCertSha256", "pinnedPeerCertificateSha256"]);
        p.verify_name = s(tls, "verifyPeerCertByName");
    }
    let r = obj(st, "realitySettings");
    if p.security == "reality" && r.is_object() {
        p.sni = s(r, "serverName");
        p.fingerprint = s(r, "fingerprint");
        p.public_key = first(r, &["publicKey", "password"]);
        p.short_id = s(r, "shortId");
        p.spider_x = s(r, "spiderX");
    }
    match p.network.as_str() {
        "ws" => {
            let o = obj(st, "wsSettings");
            p.path = s(o, "path");
            p.host = if s(o, "host").is_empty() { host_header(obj(o, "headers")) } else { s(o, "host") };
        }
        "httpupgrade" => {
            let o = obj(st, "httpupgradeSettings");
            p.path = s(o, "path");
            p.host = s(o, "host");
        }
        "grpc" => {
            let o = obj(st, "grpcSettings");
            p.path = s(o, "serviceName");
            p.host = s(o, "authority");
            if truthy(o, "multiMode") {
                p.header_type = "multi".into();
            }
        }
        "xhttp" => {
            let o = if obj(st, "xhttpSettings").is_object() { obj(st, "xhttpSettings") } else { obj(st, "splithttpSettings") };
            p.path = s(o, "path");
            p.host = s(o, "host");
            p.header_type = s(o, "mode");
        }
        "tcp" => {
            let o = if obj(st, "rawSettings").is_object() { obj(st, "rawSettings") } else { obj(st, "tcpSettings") };
            let h = obj(o, "header");
            if s(h, "type") == "http" {
                p.header_type = "http".into();
                let req = obj(h, "request");
                p.path = list(req, "path");
                p.host = host_header(obj(req, "headers"));
            }
        }
        _ => {}
    }
}

fn xray_outbound(v: &Value, remarks: &str) -> Option<Profile> {
    let set = obj(v, "settings");
    // три записи одного и того же: vnext[0].users[0], servers[0](.users[0]) и плоская (Xray 25+)
    let node = set.get("vnext").or_else(|| set.get("servers")).and_then(|x| x.get(0)).unwrap_or(set);
    let user = node.get("users").and_then(|x| x.get(0)).unwrap_or(node);
    let tag = s(v, "tag");
    let mut p = Profile {
        remarks: if remarks.is_empty() { tag } else { remarks.to_string() },
        address: s(node, "address"),
        port: port(node, "port"),
        ..Default::default()
    };
    match s(v, "protocol").as_str() {
        "vless" => {
            p.protocol = Protocol::Vless;
            p.id_or_password = s(user, "id");
            p.method = s(user, "encryption");
            p.flow = s(user, "flow");
        }
        "vmess" => {
            p.protocol = Protocol::Vmess;
            p.id_or_password = s(user, "id");
            p.method = s(user, "security");
        }
        "trojan" => {
            p.protocol = Protocol::Trojan;
            p.id_or_password = s(node, "password");
        }
        "shadowsocks" => {
            p.protocol = Protocol::Shadowsocks;
            p.method = s(node, "method");
            p.id_or_password = s(node, "password");
        }
        "socks" => {
            p.protocol = Protocol::Socks;
            p.username = s(user, "user");
            p.id_or_password = s(user, "pass");
        }
        "http" => {
            p.protocol = Protocol::Http;
            p.username = s(user, "user");
            p.id_or_password = s(user, "pass");
        }
        "wireguard" => {
            p.protocol = Protocol::WireGuard;
            p.id_or_password = s(set, "secretKey");
            p.local_address = list(set, "address");
            p.reserved = wg_reserved(set, "reserved");
            p.mtu = s(set, "mtu").parse().unwrap_or(0);
            let peer = set.get("peers").and_then(|x| x.get(0))?;
            p.public_key = s(peer, "publicKey");
            p.secret = s(peer, "preSharedKey");
            let ep = s(peer, "endpoint");
            let (h, port) = ep.rsplit_once(':')?;
            p.address = h.to_string();
            p.port = port.parse().ok()?;
            return finish(p);
        }
        _ => return None,
    }
    xray_stream(&mut p, obj(v, "streamSettings"));
    if p.protocol == Protocol::Http && p.security != "tls" {
        p.security = "none".into();
    }
    finish(p)
}

// ───────────────────────── SIP008 ─────────────────────────

fn sip008_server(v: &Value) -> Option<Profile> {
    let mut p = Profile {
        protocol: Protocol::Shadowsocks,
        remarks: first(v, &["remarks", "name"]),
        address: s(v, "server"),
        port: port(v, "server_port"),
        method: s(v, "method"),
        id_or_password: s(v, "password"),
        ..Default::default()
    };
    let plugin = s(v, "plugin");
    if !plugin.is_empty() && !links::apply_ss_plugin(&mut p, &format!("{plugin};{}", s(v, "plugin_opts"))) {
        return None;
    }
    finish(p)
}

// ───────────────────────── определение формата ─────────────────────────

fn array<'a>(v: &'a Value, k: &str) -> &'a [Value] {
    v.get(k).and_then(|x| x.as_array()).map(|a| a.as_slice()).unwrap_or(&[])
}

fn from_config(v: &Value, out: &mut Vec<Profile>) {
    // Clash в виде JSON
    for x in array(v, "proxies") {
        out.extend(clash_proxy(x));
    }
    let outbounds = array(v, "outbounds");
    if outbounds.iter().any(|o| o.get("protocol").is_some()) {
        // конфигурация Xray: имя — из remarks, если узел один
        let remarks = s(v, "remarks");
        let found: Vec<Profile> = outbounds.iter().filter_map(|o| xray_outbound(o, "")).collect();
        let single = found.len() == 1;
        for mut p in found {
            if single && !remarks.is_empty() {
                p.remarks = remarks.clone();
            } else if p.remarks.is_empty() || p.remarks == "proxy" {
                p.remarks = remarks.clone();
            }
            out.push(p);
        }
    } else {
        for x in outbounds.iter().chain(array(v, "endpoints")) {
            out.extend(singbox_outbound(x));
        }
    }
    // SIP008
    if v.get("outbounds").is_none() {
        for x in array(v, "servers") {
            out.extend(sip008_server(x));
        }
    }
    // одиночный узел
    if v.get("protocol").is_some() && v.get("settings").is_some() {
        out.extend(xray_outbound(v, ""));
    } else if v.get("type").is_some() && v.get("server").is_some() {
        out.extend(singbox_outbound(v).or_else(|| clash_proxy(v)));
    }
}

pub fn from_json(v: &Value) -> Vec<Profile> {
    let mut out = Vec::new();
    match v {
        // массив конфигураций Xray (так отдают подписки некоторые панели) или узлов
        Value::Array(items) => {
            for x in items {
                from_config(x, &mut out);
            }
        }
        Value::Object(_) => from_config(v, &mut out),
        _ => {}
    }
    out
}

fn looks_like_yaml(text: &str) -> bool {
    text.lines().any(|l| {
        let l = l.trim_end();
        l == "proxies:" || l.starts_with("proxies: ") || l.starts_with("proxies:\t")
    })
}

fn parse_inner(text: &str, depth: u8) -> Vec<Profile> {
    let text = text.trim().trim_start_matches('\u{feff}');
    if text.is_empty() {
        return Vec::new();
    }
    if text.starts_with('{') || text.starts_with('[') {
        if let Ok(v) = serde_json::from_str::<Value>(text) {
            let out = from_json(&v);
            if !out.is_empty() {
                return out;
            }
        }
    }
    let out = links::parse_lines(text);
    if !out.is_empty() {
        return out;
    }
    if looks_like_yaml(text) {
        if let Ok(v) = serde_yaml::from_str::<Value>(text) {
            let out = from_json(&v);
            if !out.is_empty() {
                return out;
            }
        }
    }
    if depth == 0 {
        if let Some(dec) = links::b64_decode(text) {
            if let Ok(inner) = String::from_utf8(dec) {
                return parse_inner(&inner, 1);
            }
        }
    }
    Vec::new()
}

/// Разбор текста в любом поддерживаемом формате.
pub fn parse_any(text: &str) -> Vec<Profile> {
    parse_inner(text, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clash_yaml() {
        let y = r#"
port: 7890
proxies:
  - {name: "🇩🇪 vless", type: vless, server: de.example.com, port: 443, uuid: 0a6b0b6f-9e4c-4d0c-9f3a-1f2e3d4c5b6a, network: tcp, tls: true, udp: true, flow: xtls-rprx-vision, servername: www.microsoft.com, reality-opts: {public-key: Y8dqSZ0mhh1sV-hcQSbPGI2xC5NUrq6rLDf2C_RXKCk, short-id: 6ba85179}, client-fingerprint: chrome}
  - name: vmess-ws
    type: vmess
    server: 1.2.3.4
    port: 8443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: auto
    tls: true
    skip-cert-verify: true
    network: ws
    ws-opts:
      path: /ray
      headers:
        Host: cdn.example.com
      max-early-data: 2048
      early-data-header-name: Sec-WebSocket-Protocol
  - {name: ss, type: ss, server: 5.6.7.8, port: 8388, cipher: aes-256-gcm, password: "p@ss"}
  - {name: ss-ws, type: ss, server: 5.6.7.9, port: 443, cipher: aes-128-gcm, password: x, plugin: v2ray-plugin, plugin-opts: {mode: websocket, tls: true, host: a.example.com, path: /p, mux: false}}
  - {name: ss-obfs, type: ss, server: 5.6.7.9, port: 443, cipher: aes-128-gcm, password: x, plugin: obfs, plugin-opts: {mode: http, host: bing.com}}
  - {name: hy2, type: hysteria2, server: h.example.com, port: 443, ports: 20000-30000, password: pw, obfs: salamander, obfs-password: op, sni: h.example.com, skip-cert-verify: false}
  - {name: tuic, type: tuic, server: t.example.com, port: 443, uuid: 0a6b0b6f-9e4c-4d0c-9f3a-1f2e3d4c5b6a, password: tp, congestion-controller: cubic, udp-relay-mode: quic, alpn: [h3]}
  - {name: trojan-grpc, type: trojan, server: tr.example.com, port: 443, password: tpw, network: grpc, grpc-opts: {grpc-service-name: svc}, sni: tr.example.com}
  - {name: wg, type: wireguard, server: 162.159.192.1, port: 2408, ip: 172.16.0.2, ipv6: "2606:4700::1", private-key: aaa=, public-key: bbb=, reserved: [1, 2, 3], mtu: 1280}
  - {name: any, type: anytls, server: a.example.com, port: 443, password: ap, client-fingerprint: chrome}
  - {name: s5, type: socks5, server: 9.9.9.9, port: 1080, username: u, password: p}
proxy-groups: []
"#;
        let v = parse_any(y);
        let names: Vec<&str> = v.iter().map(|p| p.remarks.as_str()).collect();
        assert_eq!(names, ["🇩🇪 vless", "vmess-ws", "ss", "ss-ws", "hy2", "tuic", "trojan-grpc", "wg", "any", "s5"]);
        assert_eq!(v[0].security, "reality");
        assert_eq!(v[0].short_id, "6ba85179");
        assert_eq!(v[0].flow, "xtls-rprx-vision");
        assert_eq!(v[1].path, "/ray?ed=2048");
        assert_eq!(v[1].host, "cdn.example.com");
        assert!(v[1].allow_insecure);
        assert_eq!(v[2].id_or_password, "p@ss");
        assert_eq!((v[3].network.as_str(), v[3].security.as_str(), v[3].path.as_str()), ("ws", "tls", "/p"));
        assert_eq!(v[4].ports, "20000-30000");
        assert_eq!(v[4].obfs_password, "op");
        assert_eq!((v[5].congestion.as_str(), v[5].udp_relay_mode.as_str(), v[5].alpn.as_str()), ("cubic", "quic", "h3"));
        assert_eq!((v[6].network.as_str(), v[6].path.as_str(), v[6].security.as_str()), ("grpc", "svc", "tls"));
        assert_eq!(v[7].protocol, Protocol::WireGuard);
        assert_eq!(v[7].local_address, "172.16.0.2,2606:4700::1");
        assert_eq!(v[7].reserved, "1,2,3");
    }

    #[test]
    fn singbox_json() {
        let j = r#"{"log":{},"outbounds":[
          {"type":"selector","tag":"auto","outbounds":["a"]},
          {"type":"vless","tag":"a","server":"1.1.1.1","server_port":443,"uuid":"0a6b0b6f-9e4c-4d0c-9f3a-1f2e3d4c5b6a","flow":"xtls-rprx-vision",
           "tls":{"enabled":true,"server_name":"x.com","utls":{"enabled":true,"fingerprint":"chrome"},"reality":{"enabled":true,"public_key":"PBK","short_id":"ab"}}},
          {"type":"trojan","tag":"b","server":"b.com","server_port":443,"password":"pw","tls":{"enabled":true,"insecure":true,"alpn":["h2","http/1.1"]},
           "transport":{"type":"ws","path":"/w","headers":{"Host":"h.com"},"max_early_data":2048,"early_data_header_name":"Sec-WebSocket-Protocol"}},
          {"type":"hysteria2","tag":"c","server":"c.com","server_ports":["2080:3000"],"password":"p","obfs":{"type":"salamander","password":"o"},"tls":{"enabled":true}},
          {"type":"shadowsocks","tag":"d","server":"d.com","server_port":8388,"method":"2022-blake3-aes-128-gcm","password":"k"},
          {"type":"naive","tag":"n","server":"n.com","server_port":443,"username":"u","password":"p","tls":{"enabled":true}},
          {"type":"direct","tag":"direct"}],
          "endpoints":[{"type":"wireguard","tag":"wg","address":["10.0.0.2/32"],"private_key":"PRIV","mtu":1408,
            "peers":[{"address":"e.com","port":51820,"public_key":"PUB","pre_shared_key":"PSK","allowed_ips":["0.0.0.0/0"],"reserved":[7,8,9]}]}]}"#;
        let v = parse_any(j);
        assert_eq!(v.iter().map(|p| p.remarks.as_str()).collect::<Vec<_>>(), ["a", "b", "c", "d", "n", "wg"]);
        assert_eq!((v[0].security.as_str(), v[0].public_key.as_str(), v[0].fingerprint.as_str()), ("reality", "PBK", "chrome"));
        assert_eq!((v[1].path.as_str(), v[1].host.as_str(), v[1].alpn.as_str()), ("/w?ed=2048", "h.com", "h2,http/1.1"));
        assert_eq!((v[2].port, v[2].ports.as_str()), (2080, "2080-3000"));
        assert_eq!(v[4].protocol, Protocol::Naive);
        assert_eq!((v[5].address.as_str(), v[5].port, v[5].reserved.as_str(), v[5].mtu), ("e.com", 51820, "7,8,9", 1408));
    }

    #[test]
    fn xray_json_and_array() {
        let one = r#"{"remarks":"Мой сервер","outbounds":[
          {"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"x.com","port":443,"users":[{"id":"0a6b0b6f-9e4c-4d0c-9f3a-1f2e3d4c5b6a","encryption":"none","flow":"xtls-rprx-vision"}]}]},
           "streamSettings":{"network":"raw","security":"reality","realitySettings":{"serverName":"s.com","fingerprint":"chrome","publicKey":"PBK","shortId":"01","spiderX":"/"}}},
          {"tag":"direct","protocol":"freedom"},{"tag":"block","protocol":"blackhole"}]}"#;
        let v = parse_any(one);
        assert_eq!(v.len(), 1);
        assert_eq!((v[0].remarks.as_str(), v[0].network.as_str(), v[0].sni.as_str(), v[0].public_key.as_str()), ("Мой сервер", "tcp", "s.com", "PBK"));
        let many = format!(
            r#"[{one},{{"remarks":"ws","outbounds":[{{"protocol":"vmess","settings":{{"vnext":[{{"address":"y.com","port":80,"users":[{{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","security":"zero"}}]}}]}},
            "streamSettings":{{"network":"ws","wsSettings":{{"path":"/p","headers":{{"Host":"h.y.com"}}}}}}}}]}},
            {{"remarks":"ss","outbounds":[{{"protocol":"shadowsocks","settings":{{"servers":[{{"address":"z.com","port":8388,"method":"aes-256-gcm","password":"pw"}}]}}}}]}},
            {{"remarks":"flat","outbounds":[{{"protocol":"trojan","settings":{{"address":"t.com","port":443,"password":"tp"}},
              "streamSettings":{{"network":"grpc","security":"tls","grpcSettings":{{"serviceName":"g","multiMode":true}},"tlsSettings":{{"serverName":"t.com","allowInsecure":true}}}}}}]}}]"#
        );
        let v = parse_any(&many);
        assert_eq!(v.iter().map(|p| p.remarks.as_str()).collect::<Vec<_>>(), ["Мой сервер", "ws", "ss", "flat"]);
        assert_eq!((v[1].method.as_str(), v[1].host.as_str(), v[1].path.as_str()), ("zero", "h.y.com", "/p"));
        assert_eq!(v[2].id_or_password, "pw");
        assert_eq!((v[3].header_type.as_str(), v[3].path.as_str(), v[3].allow_insecure), ("multi", "g", true));
    }

    #[test]
    fn sip008_and_base64() {
        let j = r#"{"version":1,"servers":[{"id":"1","remarks":"ss1","server":"a.com","server_port":8388,"password":"p","method":"chacha20-ietf-poly1305"}]}"#;
        let v = parse_any(j);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].method, "chacha20-ietf-poly1305");
        use base64::Engine;
        let b = base64::engine::general_purpose::STANDARD.encode(j);
        assert_eq!(parse_any(&b).len(), 1);
        let links = "trojan://pw@a.com:443#t\nvless://0a6b0b6f-9e4c-4d0c-9f3a-1f2e3d4c5b6a@b.com:443?type=ws&security=tls&path=%2Fw&ed=2048#v";
        let v = parse_any(&base64::engine::general_purpose::STANDARD.encode(links));
        assert_eq!(v.len(), 2);
        assert_eq!(v[1].path, "/w?ed=2048");
        assert!(parse_any("просто текст").is_empty());
    }
}
