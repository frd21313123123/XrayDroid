//! Журнал: кольцевой буфер в памяти + файл (общий для процессов UI и VPN).

use std::collections::VecDeque;
use std::io::Write;
use std::path::PathBuf;
use std::sync::OnceLock;

use parking_lot::Mutex;

struct State {
    ring: VecDeque<String>,
    file: Option<PathBuf>,
    sink: Option<fn(&str)>,
}

static STATE: OnceLock<Mutex<State>> = OnceLock::new();
static LOGGER: Logger = Logger;

fn state() -> &'static Mutex<State> {
    STATE.get_or_init(|| Mutex::new(State { ring: VecDeque::new(), file: None, sink: None }))
}

struct Logger;

impl log::Log for Logger {
    fn enabled(&self, m: &log::Metadata) -> bool {
        m.target().starts_with("xd_") || m.level() <= log::Level::Warn
    }
    fn log(&self, r: &log::Record) {
        if !self.enabled(r.metadata()) {
            return;
        }
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
        // время по UTC+3 — для отображения достаточно часов/минут/секунд
        let t = (now + 3 * 3600) % 86400;
        let line = format!("{:02}:{:02}:{:02} {} {}", t / 3600, (t / 60) % 60, t % 60, short(r.level()), r.args());
        push(line);
    }
    fn flush(&self) {}
}

fn short(l: log::Level) -> &'static str {
    match l {
        log::Level::Error => "E",
        log::Level::Warn => "W",
        log::Level::Info => "I",
        _ => "D",
    }
}

pub fn push(line: String) {
    let mut s = state().lock();
    if let Some(sink) = s.sink {
        sink(&line);
    }
    if let Some(f) = &s.file {
        if let Ok(meta) = std::fs::metadata(f) {
            if meta.len() > 512 * 1024 {
                let _ = std::fs::rename(f, f.with_extension("old"));
            }
        }
        if let Ok(mut fh) = std::fs::OpenOptions::new().create(true).append(true).open(f) {
            let _ = writeln!(fh, "{line}");
        }
    }
    s.ring.push_back(line);
    while s.ring.len() > 1000 {
        s.ring.pop_front();
    }
}

/// Инициализация логгера. Повторные вызовы только меняют файл.
pub fn init(file: Option<PathBuf>, debug: bool) {
    state().lock().file = file;
    let _ = log::set_logger(&LOGGER);
    log::set_max_level(if debug { log::LevelFilter::Debug } else { log::LevelFilter::Info });
}

pub fn set_sink(f: fn(&str)) {
    state().lock().sink = Some(f);
}

pub fn ring() -> Vec<String> {
    state().lock().ring.iter().cloned().collect()
}

/// Последние строки из файла журнала (включая записи процесса VPN).
pub fn tail_file(max: usize) -> Vec<String> {
    let f = state().lock().file.clone();
    let Some(f) = f else { return ring() };
    let text = std::fs::read_to_string(&f).unwrap_or_default();
    let lines: Vec<String> = text.lines().map(|s| s.to_string()).collect();
    let n = lines.len();
    lines[n.saturating_sub(max)..].to_vec()
}

pub fn clear() {
    let f = {
        let mut s = state().lock();
        s.ring.clear();
        s.file.clone()
    };
    if let Some(f) = f {
        let _ = std::fs::write(&f, b"");
    }
}
