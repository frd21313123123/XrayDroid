//! Определение домена по первым байтам соединения (TLS SNI / HTTP Host).

pub fn sniff(data: &[u8]) -> Option<(&'static str, Option<String>)> {
    if let Some(sni) = tls_sni(data) {
        return Some(("tls", sni));
    }
    http_host(data).map(|h| ("http", h))
}

fn tls_sni(b: &[u8]) -> Option<Option<String>> {
    if b.len() < 6 || b[0] != 0x16 || b[1] != 0x03 || b[5] != 0x01 {
        return None;
    }
    let mut p = 5 + 4 + 2 + 32;
    let sid = *b.get(p)? as usize;
    p += 1 + sid;
    let cs = u16::from_be_bytes([*b.get(p)?, *b.get(p + 1)?]) as usize;
    p += 2 + cs;
    let cm = *b.get(p)? as usize;
    p += 1 + cm;
    let el = u16::from_be_bytes([*b.get(p)?, *b.get(p + 1)?]) as usize;
    p += 2;
    let end = (p + el).min(b.len());
    while p + 4 <= end {
        let t = u16::from_be_bytes([b[p], b[p + 1]]);
        let l = u16::from_be_bytes([b[p + 2], b[p + 3]]) as usize;
        if t == 0 {
            let body = b.get(p + 4..p + 4 + l)?;
            // list_len(2) type(1) name_len(2) name
            if body.len() >= 5 && body[2] == 0 {
                let nl = u16::from_be_bytes([body[3], body[4]]) as usize;
                let name = body.get(5..5 + nl)?;
                return Some(Some(String::from_utf8_lossy(name).to_ascii_lowercase()));
            }
        }
        p += 4 + l;
    }
    Some(None)
}

fn http_host(b: &[u8]) -> Option<Option<String>> {
    const METHODS: [&[u8]; 9] = [b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"CONNECT ", b"TRACE "];
    if !METHODS.iter().any(|m| b.starts_with(m)) {
        return None;
    }
    let text = String::from_utf8_lossy(&b[..b.len().min(4096)]);
    for line in text.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("host") {
                let v = v.trim();
                let host = if let Some(r) = v.strip_prefix('[') {
                    r.split(']').next().unwrap_or("")
                } else {
                    v.rsplit_once(':').filter(|(_, p)| p.parse::<u16>().is_ok()).map(|(h, _)| h).unwrap_or(v)
                };
                return Some(Some(host.to_ascii_lowercase()));
            }
        }
    }
    Some(None)
}

#[cfg(test)]
mod tests {
    #[test]
    fn http() {
        let r = super::sniff(b"GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n").unwrap();
        assert_eq!(r, ("http", Some("example.com".into())));
    }
}
