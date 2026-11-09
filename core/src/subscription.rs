//! Подписки и загрузка файлов по HTTP(S).

use std::io::{self, Read, Write};
use std::path::Path;
use std::time::Duration;

use crate::common::io_err;
use crate::config::{Profile, Subscription};

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(60)))
        .http_status_as_error(false)
        .build()
        .into()
}

/// Текст ответа и заголовки (имя → значение, имена в нижнем регистре).
pub fn fetch_text(url: &str, user_agent: &str) -> io::Result<(String, Vec<(String, String)>)> {
    let mut resp = agent().get(url).header("User-Agent", user_agent).call().map_err(|e| io_err(format!("{e}")))?;
    if !resp.status().is_success() {
        return Err(io_err(format!("HTTP {}", resp.status())));
    }
    let headers = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_ascii_lowercase(), String::from_utf8_lossy(v.as_bytes()).into_owned()))
        .collect();
    let text = resp
        .body_mut()
        .with_config()
        .limit(32 * 1024 * 1024)
        .read_to_string()
        .map_err(|e| io_err(format!("{e}")))?;
    Ok((text, headers))
}

/// Результат обновления подписки.
pub struct SubUpdate {
    pub profiles: Vec<Profile>,
    /// Название из заголовка profile-title (если есть)
    pub title: Option<String>,
    /// Трафик и срок из subscription-userinfo, в читаемом виде
    pub info: String,
}

fn fmt_gb(b: u64) -> String {
    format!("{:.1} ГБ", b as f64 / 1073741824.0)
}

/// Разбор заголовка `subscription-userinfo: upload=..; download=..; total=..; expire=..`.
pub fn parse_userinfo(v: &str) -> String {
    let mut up = 0u64;
    let mut down = 0u64;
    let mut total = 0u64;
    let mut expire = 0i64;
    for part in v.split(';') {
        if let Some((k, val)) = part.trim().split_once('=') {
            let n = val.trim().parse::<f64>().unwrap_or(0.0);
            match k.trim() {
                "upload" => up = n as u64,
                "download" => down = n as u64,
                "total" => total = n as u64,
                "expire" => expire = n as i64,
                _ => {}
            }
        }
    }
    let mut out = Vec::new();
    let used = up + down;
    if total > 0 {
        out.push(format!("трафик {} из {}", fmt_gb(used), fmt_gb(total)));
    } else if used > 0 {
        out.push(format!("использовано {}", fmt_gb(used)));
    }
    if expire > 0 {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
        let days = (expire - now) / 86400;
        out.push(if days >= 0 { format!("осталось {days} дн") } else { "истекла".into() });
    }
    out.join(" · ")
}

fn decode_title(v: &str) -> String {
    let v = v.trim();
    if let Some(b) = v.strip_prefix("base64:") {
        if let Some(d) = crate::links::b64_decode(b) {
            return String::from_utf8_lossy(&d).trim().to_string();
        }
    }
    percent_encoding::percent_decode_str(v).decode_utf8_lossy().trim().to_string()
}

/// Скачивает подписку и возвращает профили (с sub_id подписки).
pub fn update(sub: &Subscription, user_agent: &str) -> io::Result<SubUpdate> {
    let (text, headers) = fetch_text(sub.url.trim(), user_agent)?;
    let mut list = crate::links::parse_many(&text);
    if list.is_empty() {
        return Err(io_err("в подписке не найдено поддерживаемых серверов"));
    }
    for p in &mut list {
        p.sub_id = sub.id.clone();
    }
    let h = |name: &str| headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone());
    Ok(SubUpdate {
        profiles: list,
        title: h("profile-title").map(|v| decode_title(&v)).filter(|t| !t.is_empty()),
        info: h("subscription-userinfo").map(|v| parse_userinfo(&v)).unwrap_or_default(),
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn userinfo() {
        let s = super::parse_userinfo("upload=1073741824; download=1073741824; total=10737418240; expire=0");
        assert_eq!(s, "трафик 2.0 ГБ из 10.0 ГБ");
        assert_eq!(super::decode_title("base64:0JzQvtC5IFZQTg=="), "Мой VPN");
    }
}

/// Скачивание файла (geoip.dat / geosite.dat) с атомарной заменой.
pub fn download(url: &str, dest: &Path, progress: &dyn Fn(u64)) -> io::Result<u64> {
    let resp = agent().get(url).header("User-Agent", "XrayDroid").call().map_err(|e| io_err(format!("{e}")))?;
    if !resp.status().is_success() {
        return Err(io_err(format!("HTTP {}", resp.status())));
    }
    let tmp = dest.with_extension("part");
    let mut f = std::fs::File::create(&tmp)?;
    let mut r = resp.into_body().into_reader();
    let mut buf = vec![0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        f.write_all(&buf[..n])?;
        total += n as u64;
        progress(total);
    }
    f.sync_all()?;
    drop(f);
    if total < 1024 {
        let _ = std::fs::remove_file(&tmp);
        return Err(io_err("скачан слишком маленький файл"));
    }
    std::fs::rename(&tmp, dest)?;
    Ok(total)
}
