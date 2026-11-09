//! Чтение geosite.dat / geoip.dat (формат v2fly, protobuf) без зависимостей.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::Path;

struct Pb<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Pb<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, p: 0 }
    }
    fn done(&self) -> bool {
        self.p >= self.b.len()
    }
    fn varint(&mut self) -> Option<u64> {
        let mut v = 0u64;
        let mut shift = 0;
        loop {
            let byte = *self.b.get(self.p)?;
            self.p += 1;
            v |= ((byte & 0x7f) as u64) << shift;
            if byte & 0x80 == 0 {
                return Some(v);
            }
            shift += 7;
            if shift > 63 {
                return None;
            }
        }
    }
    /// (номер поля, тип, данные для LEN / значение для VARINT)
    fn field(&mut self) -> Option<(u32, Field<'a>)> {
        let key = self.varint()?;
        let num = (key >> 3) as u32;
        match key & 7 {
            0 => Some((num, Field::Varint(self.varint()?))),
            2 => {
                let l = self.varint()? as usize;
                let d = self.b.get(self.p..self.p + l)?;
                self.p += l;
                Some((num, Field::Bytes(d)))
            }
            1 => {
                self.p += 8;
                Some((num, Field::Varint(0)))
            }
            5 => {
                self.p += 4;
                Some((num, Field::Varint(0)))
            }
            _ => None,
        }
    }
}

enum Field<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
}

/// Тип домена в geosite: Plain(подстрока)=0, Regex=1, Domain(суффикс)=2, Full=3
#[derive(Clone, Debug)]
pub struct GeoDomain {
    pub kind: u8,
    pub value: String,
    pub attrs: Vec<String>,
}

fn entry_code(entry: &[u8]) -> Option<String> {
    let mut pb = Pb::new(entry);
    while !pb.done() {
        if let (1, Field::Bytes(b)) = pb.field()? {
            return Some(String::from_utf8_lossy(b).to_ascii_lowercase());
        }
    }
    None
}

/// Загружает домены для указанных кодов (регистр не важен).
pub fn load_geosite(path: &Path, codes: &HashSet<String>) -> HashMap<String, Vec<GeoDomain>> {
    let mut out = HashMap::new();
    let Ok(data) = std::fs::read(path) else { return out };
    let mut top = Pb::new(&data);
    while !top.done() {
        let Some((num, f)) = top.field() else { break };
        let (1, Field::Bytes(entry)) = (num, f) else { continue };
        let Some(code) = entry_code(entry) else { continue };
        if !codes.contains(&code) {
            continue;
        }
        let mut list = Vec::new();
        let mut pb = Pb::new(entry);
        while !pb.done() {
            let Some((n, f)) = pb.field() else { break };
            if let (2, Field::Bytes(d)) = (n, f) {
                let mut dp = Pb::new(d);
                let mut gd = GeoDomain { kind: 0, value: String::new(), attrs: vec![] };
                while !dp.done() {
                    match dp.field() {
                        Some((1, Field::Varint(v))) => gd.kind = v as u8,
                        Some((2, Field::Bytes(s))) => gd.value = String::from_utf8_lossy(s).to_ascii_lowercase(),
                        Some((3, Field::Bytes(a))) => {
                            let mut ap = Pb::new(a);
                            if let Some((1, Field::Bytes(k))) = ap.field() {
                                gd.attrs.push(String::from_utf8_lossy(k).to_ascii_lowercase());
                            }
                        }
                        Some(_) => {}
                        None => break,
                    }
                }
                list.push(gd);
            }
        }
        out.insert(code, list);
    }
    out
}

#[derive(Clone, Debug, Default)]
pub struct GeoIp {
    pub cidrs: Vec<(IpAddr, u8)>,
    pub reverse: bool,
}

pub fn load_geoip(path: &Path, codes: &HashSet<String>) -> HashMap<String, GeoIp> {
    let mut out = HashMap::new();
    let Ok(data) = std::fs::read(path) else { return out };
    let mut top = Pb::new(&data);
    while !top.done() {
        let Some((num, f)) = top.field() else { break };
        let (1, Field::Bytes(entry)) = (num, f) else { continue };
        let Some(code) = entry_code(entry) else { continue };
        if !codes.contains(&code) {
            continue;
        }
        let mut g = GeoIp::default();
        let mut pb = Pb::new(entry);
        while !pb.done() {
            match pb.field() {
                Some((2, Field::Bytes(c))) => {
                    let mut cp = Pb::new(c);
                    let mut ip: Option<IpAddr> = None;
                    let mut prefix = 0u8;
                    while !cp.done() {
                        match cp.field() {
                            Some((1, Field::Bytes(b))) => {
                                ip = match b.len() {
                                    4 => Some(IpAddr::from(<[u8; 4]>::try_from(b).unwrap())),
                                    16 => Some(IpAddr::from(<[u8; 16]>::try_from(b).unwrap())),
                                    _ => None,
                                }
                            }
                            Some((2, Field::Varint(v))) => prefix = v as u8,
                            Some(_) => {}
                            None => break,
                        }
                    }
                    if let Some(ip) = ip {
                        g.cidrs.push((ip, prefix));
                    }
                }
                Some((3, Field::Varint(v))) => g.reverse = v != 0,
                Some(_) => {}
                None => break,
            }
        }
        out.insert(code, g);
    }
    out
}

/// Список кодов в файле (для подсказок в UI).
pub fn list_codes(path: &Path) -> Vec<String> {
    let mut v = Vec::new();
    let Ok(data) = std::fs::read(path) else { return v };
    let mut top = Pb::new(&data);
    while !top.done() {
        let Some((num, f)) = top.field() else { break };
        let (1, Field::Bytes(entry)) = (num, f) else { continue };
        if let Some(c) = entry_code(entry) {
            v.push(c);
        }
    }
    v.sort();
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn varint(mut v: u64, out: &mut Vec<u8>) {
        loop {
            let b = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                out.push(b);
                break;
            }
            out.push(b | 0x80);
        }
    }
    fn lenf(num: u32, data: &[u8], out: &mut Vec<u8>) {
        varint(((num as u64) << 3) | 2, out);
        varint(data.len() as u64, out);
        out.extend_from_slice(data);
    }

    #[test]
    fn parse_geosite() {
        let mut dom = Vec::new();
        varint(1 << 3, &mut dom);
        varint(2, &mut dom);
        lenf(2, b"Example.com", &mut dom);
        let mut site = Vec::new();
        lenf(1, b"TEST", &mut site);
        lenf(2, &dom, &mut site);
        let mut file = Vec::new();
        lenf(1, &site, &mut file);
        let p = std::env::temp_dir().join("xd_geosite_test.dat");
        std::fs::write(&p, &file).unwrap();
        let m = load_geosite(&p, &["test".to_string()].into_iter().collect());
        let d = &m["test"][0];
        assert_eq!(d.kind, 2);
        assert_eq!(d.value, "example.com");
        assert_eq!(list_codes(&p), vec!["test"]);
    }
}
