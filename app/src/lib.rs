//! XrayDroid — Android VPN-клиент на Rust (UI на Slint).

slint::include_modules!();

pub mod state;
pub mod status;
pub mod ui;

#[cfg(target_os = "android")]
mod android;

/// Возможности платформы, которые нужны интерфейсу.
pub trait Host: Send + Sync {
    fn start_vpn(&self);
    fn stop_vpn(&self);
    fn get_clipboard(&self) -> Option<String>;
    fn set_clipboard(&self, text: &str);
    /// (package, label)
    fn installed_apps(&self) -> Vec<(String, String)>;
}

/// Заглушка для десктопа (скриншоты и отладка интерфейса).
pub struct DesktopHost;

impl Host for DesktopHost {
    fn start_vpn(&self) {
        status::on_service(true, "", 0, 0, state::now_secs() * 1000);
    }
    fn stop_vpn(&self) {
        status::on_service(false, "", 0, 0, 0);
    }
    fn get_clipboard(&self) -> Option<String> {
        None
    }
    fn set_clipboard(&self, _: &str) {}
    fn installed_apps(&self) -> Vec<(String, String)> {
        [
            ("com.openai.chatgpt", "ChatGPT"),
            ("com.google.android.apps.bard", "Gemini"),
            ("com.discord", "Discord"),
            ("org.telegram.messenger", "Telegram"),
            ("com.android.chrome", "Chrome"),
            ("com.google.android.youtube", "YouTube"),
            ("ru.yandex.searchplugin", "Яндекс"),
        ]
        .into_iter()
        .map(|(p, l)| (p.to_string(), l.to_string()))
        .collect()
    }
}
