//! FakeDNS: отвечает на A-запросы адресами из 198.18.0.0/15 и запоминает соответствие
//! IP → домен, чтобы маршрутизировать и отправлять на сервер именно домен.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

use parking_lot::Mutex;

const BASE: u32 = 0xC612_0000; // 198.18.0.0
const SIZE: u32 = 1 << 17; // /15

pub struct FakeDns {
    inner: Mutex<Inner>,
}

struct Inner {
    next: u32,
    by_ip: HashMap<u32, String>,
    by_domain: HashMap<String, u32>,
}

pub fn is_fake(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => (u32::from(v4) & !(SIZE - 1)) == BASE,
        _ => false,
    }
}

impl Default for FakeDns {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeDns {
    pub fn new() -> Self {
        Self { inner: Mutex::new(Inner { next: 2, by_ip: HashMap::new(), by_domain: HashMap::new() }) }
    }

    pub fn lookup(&self, ip: IpAddr) -> Option<String> {
        if let IpAddr::V4(v4) = ip {
            return self.inner.lock().by_ip.get(&u32::from(v4)).cloned();
        }
        None
    }

    pub fn alloc(&self, domain: &str) -> Ipv4Addr {
        let mut g = self.inner.lock();
        if let Some(ip) = g.by_domain.get(domain) {
            return Ipv4Addr::from(*ip);
        }
        let off = g.next;
        g.next += 1;
        if g.next >= SIZE - 1 {
            g.next = 2;
        }
        let ip = BASE + off;
        if let Some(old) = g.by_ip.insert(ip, domain.to_string()) {
            g.by_domain.remove(&old);
        }
        g.by_domain.insert(domain.to_string(), ip);
        Ipv4Addr::from(ip)
    }

    /// Возвращает ответ, если запрос обрабатывается локально (A/AAAA/HTTPS),
    /// иначе None — запрос надо переслать настоящему DNS.
    pub fn answer(&self, q: &[u8]) -> Option<Vec<u8>> {
        let (name, qtype, qend) = parse_question(q)?;
        let mut resp = Vec::with_capacity(qend + 32);
        resp.extend_from_slice(&q[..2]); // id
        let rd = q[2] & 0x01;
        resp.extend_from_slice(&[0x80 | rd, 0x80]);
        resp.extend_from_slice(&[0, 1]); // qdcount
        match qtype {
            1 => {
                let ip = self.alloc(&name);
                resp.extend_from_slice(&[0, 1, 0, 0, 0, 0]);
                resp.extend_from_slice(&q[12..qend]);
                resp.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]);
                resp.extend_from_slice(&60u32.to_be_bytes());
                resp.extend_from_slice(&[0, 4]);
                resp.extend_from_slice(&ip.octets());
            }
            28 | 65 => {
                resp.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
                resp.extend_from_slice(&q[12..qend]);
            }
            _ => return None,
        }
        Some(resp)
    }
}

/// (имя, тип, конец секции вопроса)
pub fn parse_question(q: &[u8]) -> Option<(String, u16, usize)> {
    if q.len() < 12 || q[2] & 0x80 != 0 || u16::from_be_bytes([q[4], q[5]]) != 1 {
        return None;
    }
    let mut p = 12;
    let mut labels = Vec::new();
    loop {
        let l = *q.get(p)? as usize;
        p += 1;
        if l == 0 {
            break;
        }
        if l & 0xc0 != 0 {
            return None;
        }
        labels.push(String::from_utf8_lossy(q.get(p..p + l)?).to_ascii_lowercase());
        p += l;
    }
    let qtype = u16::from_be_bytes([*q.get(p)?, *q.get(p + 1)?]);
    if labels.is_empty() {
        return None;
    }
    Some((labels.join("."), qtype, p + 4))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_a() {
        let q: Vec<u8> = vec![
            0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1,
        ];
        let f = FakeDns::new();
        let r = f.answer(&q).unwrap();
        assert_eq!(&r[..2], &[0x12, 0x34]);
        let ip = Ipv4Addr::new(r[r.len() - 4], r[r.len() - 3], r[r.len() - 2], r[r.len() - 1]);
        assert!(is_fake(IpAddr::V4(ip)));
        assert_eq!(f.lookup(IpAddr::V4(ip)).as_deref(), Some("example.com"));
    }
}
