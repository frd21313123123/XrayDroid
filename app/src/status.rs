//! Статус VPN-сервиса (обновляется из Java через JNI).

use parking_lot::Mutex;

#[derive(Clone, Default)]
pub struct VpnStatus {
    pub running: bool,
    pub connecting: bool,
    pub error: String,
    pub message: String,
    pub up: u64,
    pub down: u64,
    /// Время запуска VPN, unix мс (0 — неизвестно)
    pub started_ms: i64,
}

static STATUS: Mutex<VpnStatus> = Mutex::new(VpnStatus {
    running: false,
    connecting: false,
    error: String::new(),
    message: String::new(),
    up: 0,
    down: 0,
    started_ms: 0,
});

pub fn get() -> VpnStatus {
    STATUS.lock().clone()
}

pub fn set_connecting() {
    let mut s = STATUS.lock();
    s.connecting = true;
    s.error.clear();
    s.message.clear();
}

pub fn set_stopping() {
    let mut s = STATUS.lock();
    s.connecting = true;
    s.message.clear();
}

pub fn set_message(m: &str) {
    STATUS.lock().message = m.to_string();
}

/// Сообщение от сервиса.
pub fn on_service(running: bool, error: &str, up: u64, down: u64, started_ms: i64) {
    let mut s = STATUS.lock();
    if s.running != running || !error.is_empty() {
        s.message.clear();
    }
    s.running = running;
    s.connecting = false;
    s.error = error.to_string();
    s.up = up;
    s.down = down;
    s.started_ms = started_ms;
}
