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

pub fn fetch_text(url: &str, user_agent: &str) -> io::Result<String> {
    let mut resp = agent().get(url).header("User-Agent", user_agent).call().map_err(|e| io_err(format!("{e}")))?;
    if !resp.status().is_success() {
        return Err(io_err(format!("HTTP {}", resp.status())));
    }
    resp.body_mut()
        .with_config()
        .limit(32 * 1024 * 1024)
        .read_to_string()
        .map_err(|e| io_err(format!("{e}")))
}

/// Скачивает подписку и возвращает профили (с sub_id подписки).
pub fn update(sub: &Subscription, user_agent: &str) -> io::Result<Vec<Profile>> {
    let text = fetch_text(sub.url.trim(), user_agent)?;
    let mut list = crate::links::parse_many(&text);
    if list.is_empty() {
        return Err(io_err("в подписке не найдено поддерживаемых серверов"));
    }
    for p in &mut list {
        p.sub_id = sub.id.clone();
    }
    Ok(list)
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
