//! XTLS Vision (flow = xtls-rprx-vision) поверх REALITY.
//!
//! Повторяет логику Xray-core `proxy/proxy.go`: паддинг первых пакетов
//! вложенного TLS, а после того как внутренний TLS 1.3 перешёл к передаче
//! данных — переключение на "прямую" передачу по сырому TCP без внешнего
//! шифрования (команда PaddingDirect).

use std::io;
use std::sync::Arc;

use parking_lot::Mutex;
use rand::Rng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::vless::first_payload;
use crate::common::{io_err, BoxStream};
use crate::transport::secure::SecureConn;

const CMD_CONTINUE: u8 = 0;
const CMD_END: u8 = 1;
const CMD_DIRECT: u8 = 2;
const BUF_SIZE: usize = 8192;
const MAX_CONTENT: usize = BUF_SIZE - 21;

const TLS_SERVER_HS_START: [u8; 3] = [0x16, 0x03, 0x03];
const TLS_CLIENT_HS_START: [u8; 2] = [0x16, 0x03];
const TLS_APP_DATA_START: [u8; 3] = [0x17, 0x03, 0x03];
const TLS13_SUPPORTED_VERSIONS: [u8; 6] = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];

/// Общее состояние фильтрации внутреннего TLS (разделяется чтением и записью).
struct Traffic {
    packets_to_filter: i32,
    is_tls: bool,
    is_tls12_or_above: bool,
    enable_xtls: bool,
    cipher: u16,
    remaining_server_hello: i32,
}

impl Traffic {
    fn new() -> Self {
        Self {
            packets_to_filter: 8,
            is_tls: false,
            is_tls12_or_above: false,
            enable_xtls: false,
            cipher: 0,
            remaining_server_hello: -1,
        }
    }

    /// XtlsFilterTls для одного буфера.
    fn filter(&mut self, b: &[u8]) {
        self.packets_to_filter -= 1;
        if b.len() >= 6 {
            if b[..3] == TLS_SERVER_HS_START && b[5] == 0x02 {
                self.remaining_server_hello = ((b[3] as i32) << 8 | b[4] as i32) + 5;
                self.is_tls12_or_above = true;
                self.is_tls = true;
                if b.len() >= 79 && self.remaining_server_hello >= 79 {
                    let sid_len = b[43] as usize;
                    if let Some(cs) = b.get(43 + sid_len + 1..43 + sid_len + 3) {
                        self.cipher = u16::from_be_bytes([cs[0], cs[1]]);
                    }
                }
            } else if b[..2] == TLS_CLIENT_HS_START && b[5] == 0x01 {
                self.is_tls = true;
            }
        }
        if self.remaining_server_hello > 0 {
            let end = (self.remaining_server_hello as usize).min(b.len());
            self.remaining_server_hello -= b.len() as i32;
            if b[..end].windows(6).any(|w| w == TLS13_SUPPORTED_VERSIONS) {
                // TLS_AES_128_CCM_8_SHA256 (0x1305) не поддерживает XTLS
                if matches!(self.cipher, 0x1301 | 0x1302 | 0x1303 | 0x1304) {
                    self.enable_xtls = true;
                }
                self.packets_to_filter = 0;
                return;
            } else if self.remaining_server_hello <= 0 {
                self.packets_to_filter = 0;
            }
        }
    }
}

fn is_complete_record(b: &[u8]) -> bool {
    let mut header_len = 5;
    let mut record_len = 0usize;
    let mut i = 0;
    while i < b.len() {
        if header_len > 0 {
            let d = b[i];
            i += 1;
            match header_len {
                5 if d != 0x17 => return false,
                4 | 3 if d != 0x03 => return false,
                2 => record_len = (d as usize) << 8,
                1 => record_len |= d as usize,
                _ => {}
            }
            header_len -= 1;
        } else if record_len > 0 {
            if b.len() - i < record_len {
                return false;
            }
            i += record_len;
            record_len = 0;
            header_len = 5;
        } else {
            return false;
        }
    }
    header_len == 5 && record_len == 0
}

fn pad(content: &[u8], command: u8, uuid: &mut Option<[u8; 16]>, long_padding: bool) -> Vec<u8> {
    let content_len = content.len() as i32;
    let mut rng = rand::thread_rng();
    let mut padding_len = if content_len < 900 && long_padding {
        rng.gen_range(0..500) + 900 - content_len
    } else {
        rng.gen_range(0..256)
    };
    if padding_len > BUF_SIZE as i32 - 21 - content_len {
        padding_len = BUF_SIZE as i32 - 21 - content_len;
    }
    let padding_len = padding_len.max(0) as usize;
    let mut out = Vec::with_capacity(21 + content.len() + padding_len);
    if let Some(u) = uuid.take() {
        out.extend_from_slice(&u);
    }
    out.push(command);
    out.extend_from_slice(&(content.len() as u16).to_be_bytes());
    out.extend_from_slice(&(padding_len as u16).to_be_bytes());
    out.extend_from_slice(content);
    out.resize(out.len() + padding_len, 0);
    out
}

/// Разбор паддинга входящего потока (XtlsUnpadding).
struct Unpadder {
    uuid: [u8; 16],
    remaining_command: i32,
    remaining_content: i32,
    remaining_padding: i32,
    current_command: i32,
}

impl Unpadder {
    fn new(uuid: [u8; 16]) -> Self {
        Self { uuid, remaining_command: -1, remaining_content: -1, remaining_padding: -1, current_command: 0 }
    }

    fn unpad(&mut self, mut b: &[u8]) -> Vec<u8> {
        if self.remaining_command == -1 && self.remaining_content == -1 && self.remaining_padding == -1 {
            if b.len() >= 21 && b[..16] == self.uuid {
                b = &b[16..];
                self.remaining_command = 5;
            } else {
                return b.to_vec();
            }
        }
        let mut out = Vec::with_capacity(b.len());
        while !b.is_empty() {
            if self.remaining_command > 0 {
                let d = b[0] as i32;
                b = &b[1..];
                match self.remaining_command {
                    5 => self.current_command = d,
                    4 => self.remaining_content = d << 8,
                    3 => self.remaining_content |= d,
                    2 => self.remaining_padding = d << 8,
                    1 => self.remaining_padding |= d,
                    _ => {}
                }
                self.remaining_command -= 1;
            } else if self.remaining_content > 0 {
                let n = (self.remaining_content as usize).min(b.len());
                out.extend_from_slice(&b[..n]);
                b = &b[n..];
                self.remaining_content -= n as i32;
            } else {
                let n = (self.remaining_padding.max(0) as usize).min(b.len());
                b = &b[n..];
                self.remaining_padding -= n as i32;
            }
            if self.remaining_command <= 0 && self.remaining_content <= 0 && self.remaining_padding <= 0 {
                if self.current_command == 0 {
                    self.remaining_command = 5;
                } else {
                    self.remaining_command = -1;
                    self.remaining_content = -1;
                    self.remaining_padding = -1;
                    if !b.is_empty() {
                        out.extend_from_slice(b);
                    }
                    break;
                }
            }
        }
        out
    }
}

/// XTLS Vision поверх защищённого слоя (REALITY / TLS 1.3 / VLESS Encryption).
/// `header` — заголовок запроса VLESS (с flow = xtls-rprx-vision).
pub async fn run(conn: SecureConn, uuid: [u8; 16], app: BoxStream, header: Vec<u8>) -> io::Result<()> {
    let SecureConn { mut reader, mut writer } = conn;

    let traffic = Arc::new(Mutex::new(Traffic::new()));
    let (mut app_r, mut app_w) = tokio::io::split(app);
    let last = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let started = tokio::time::Instant::now();

    // ── uplink: приложение → сервер ──
    let t_up = traffic.clone();
    let last_up = last.clone();
    let uplink = async move {
        let mut uuid_once = Some(uuid);
        let mut is_padding = true;
        let mut direct = false;
        let mut first = true;
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            let data: Vec<u8> = if first {
                first_payload(&mut app_r, 300).await?
            } else {
                let n = app_r.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                buf[..n].to_vec()
            };
            last_up.store(started.elapsed().as_secs(), std::sync::atomic::Ordering::Relaxed);
            if direct {
                writer.write_raw(&data).await?;
                continue;
            }
            if !is_padding {
                writer.write_app(&data).await?;
                continue;
            }
            let mut out = Vec::new();
            if first {
                out.extend_from_slice(&header);
                first = false;
                if data.is_empty() {
                    out.extend_from_slice(&pad(&[], CMD_CONTINUE, &mut uuid_once, true));
                    writer.write_app(&out).await?;
                    continue;
                }
            }
            let mut switch_direct = false;
            {
                let mut t = t_up.lock();
                if t.packets_to_filter > 0 {
                    t.filter(&data);
                }
                let complete = is_complete_record(&data);
                let chunks: Vec<&[u8]> = data.chunks(MAX_CONTENT).collect();
                let mut long_padding = t.is_tls;
                let last_i = chunks.len() - 1;
                for (i, c) in chunks.iter().enumerate() {
                    if t.is_tls && c.len() >= 6 && c[..3] == TLS_APP_DATA_START && complete {
                        if t.enable_xtls {
                            switch_direct = true;
                        }
                        let mut cmd = CMD_CONTINUE;
                        if i == last_i {
                            cmd = if t.enable_xtls { CMD_DIRECT } else { CMD_END };
                        }
                        out.extend_from_slice(&pad(c, cmd, &mut uuid_once, true));
                        is_padding = false;
                        long_padding = false;
                        continue;
                    } else if !t.is_tls12_or_above && t.packets_to_filter <= 1 {
                        is_padding = false;
                        out.extend_from_slice(&pad(c, CMD_END, &mut uuid_once, long_padding));
                        for rest in &chunks[i + 1..] {
                            out.extend_from_slice(rest);
                        }
                        break;
                    }
                    let mut cmd = CMD_CONTINUE;
                    if i == last_i && !is_padding {
                        cmd = if t.enable_xtls { CMD_DIRECT } else { CMD_END };
                    }
                    out.extend_from_slice(&pad(c, cmd, &mut uuid_once, long_padding));
                }
            }
            writer.write_app(&out).await?;
            if switch_direct {
                log::debug!("vision: отправка переключена в direct");
                direct = true;
            }
        }
        if direct {
            writer.shutdown_raw().await;
        } else {
            writer.close().await;
        }
        Ok::<_, io::Error>(())
    };

    // ── downlink: сервер → приложение ──
    let t_down = traffic.clone();
    let last_down = last.clone();
    let downlink = async move {
        let mut unpadder = Unpadder::new(uuid);
        let mut within_padding = true;
        let mut direct = false;
        let mut header_left: i32 = -1; // -1: ждём 2 байта заголовка
        let mut head = Vec::new();
        let mut raw = vec![0u8; 32 * 1024];
        loop {
            if direct {
                let n = reader.read_raw(&mut raw).await?;
                if n == 0 {
                    break;
                }
                last_down.store(started.elapsed().as_secs(), std::sync::atomic::Ordering::Relaxed);
                app_w.write_all(&raw[..n]).await?;
                continue;
            }
            let Some(mut data) = reader.read_app().await? else { break };
            last_down.store(started.elapsed().as_secs(), std::sync::atomic::Ordering::Relaxed);
            // заголовок ответа VLESS
            if header_left != 0 {
                let mut i = 0;
                while i < data.len() && header_left != 0 {
                    if header_left == -1 {
                        head.push(data[i]);
                        i += 1;
                        if head.len() == 2 {
                            if head[0] != 0 {
                                return Err(io_err("VLESS: неверная версия ответа"));
                            }
                            header_left = head[1] as i32;
                        }
                    } else {
                        let k = (header_left as usize).min(data.len() - i);
                        i += k;
                        header_left -= k as i32;
                    }
                }
                data.drain(..i);
                if data.is_empty() {
                    continue;
                }
            }
            let mut out = data;
            let mut switch_direct = false;
            {
                let mut t = t_down.lock();
                if within_padding || t.packets_to_filter > 0 {
                    out = unpadder.unpad(&out);
                    if unpadder.remaining_content > 0 || unpadder.remaining_padding > 0 || unpadder.current_command == 0 {
                        within_padding = true;
                    } else if unpadder.current_command == 1 {
                        within_padding = false;
                    } else if unpadder.current_command == 2 {
                        within_padding = false;
                        switch_direct = true;
                    }
                }
                if t.packets_to_filter > 0 && !out.is_empty() {
                    t.filter(&out);
                }
            }
            if switch_direct {
                // остаток уже прочитанных из TCP байт — это сырые данные
                out.extend_from_slice(&reader.take_raw());
                log::debug!("vision: приём переключён в direct");
                direct = true;
            }
            if !out.is_empty() {
                app_w.write_all(&out).await?;
            }
        }
        let _ = app_w.shutdown().await;
        Ok::<_, io::Error>(())
    };

    let watchdog = async {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            let idle = started.elapsed().as_secs() - last.load(std::sync::atomic::Ordering::Relaxed);
            if idle > crate::common::IDLE_TIMEOUT_SECS {
                break;
            }
        }
    };
    let (up_done, down_done) = (async { uplink.await }, async { downlink.await });
    tokio::pin!(up_done);
    tokio::pin!(down_done);
    let res = tokio::select! {
        r = async {
            // ждём обе стороны; после завершения одной — ограничиваем вторую
            tokio::select! {
                r = &mut up_done => {
                    let _ = tokio::time::timeout(std::time::Duration::from_secs(crate::common::IDLE_TIMEOUT_SECS), &mut down_done).await;
                    r
                }
                r = &mut down_done => {
                    let _ = tokio::time::timeout(std::time::Duration::from_secs(crate::common::HALF_CLOSE_TIMEOUT_SECS), &mut up_done).await;
                    r
                }
            }
        } => r,
        _ = watchdog => Ok(()),
    };
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pad_unpad_roundtrip() {
        let uuid = [7u8; 16];
        let mut once = Some(uuid);
        let mut stream = pad(b"hello", CMD_CONTINUE, &mut once, true);
        stream.extend(pad(b" world", CMD_END, &mut once, false));
        stream.extend_from_slice(b"RAW");
        let mut u = Unpadder::new(uuid);
        let mut out = Vec::new();
        out.extend(u.unpad(&stream[..30]));
        for c in stream[30..].chunks(7) {
            out.extend(u.unpad(c));
        }
        assert_eq!(out, b"hello worldRAW");
    }

    #[test]
    fn complete_record() {
        assert!(is_complete_record(&[0x17, 3, 3, 0, 2, 1, 2]));
        assert!(!is_complete_record(&[0x17, 3, 3, 0, 3, 1, 2]));
        assert!(!is_complete_record(&[0x16, 3, 3, 0, 2, 1, 2]));
    }
}
