//! Флаги стран в названиях серверов.
//!
//! Флаг — это пара символов Regional Indicator (🇩 + 🇪 = 🇩🇪). В Android 12+ флаги
//! вынесены из `NotoColorEmoji.ttf` в отдельный файл `NotoColorEmojiFlags.ttf` с тем же
//! именем семейства. Библиотека шрифтов Slint (fontique) берёт для эмодзи только
//! первый файл семейства — без флагов, поэтому вместо флага рисовались два квадрата.
//! Здесь файл с флагами регистрируется под собственным именем и ставится первым в
//! списке шрифтов для эмодзи. Если шрифта с флагами на устройстве нет, флаги
//! заменяются буквенным кодом страны («DE»), а не квадратами.

use std::sync::atomic::{AtomicBool, Ordering};

/// Отрисовываются ли флаги. На десктопе (скриншоты, тесты) текст не меняем.
static FLAGS_OK: AtomicBool = AtomicBool::new(true);

const RI_FIRST: u32 = 0x1F1E6; // 🇦
const RI_LAST: u32 = 0x1F1FF; // 🇿

fn regional(c: char) -> Option<char> {
    let u = c as u32;
    (RI_FIRST..=RI_LAST).contains(&u).then(|| char::from(b'A' + (u - RI_FIRST) as u8))
}

/// Найден ли шрифт, которым можно нарисовать флаги.
pub fn flags_supported() -> bool {
    FLAGS_OK.load(Ordering::Relaxed)
}

/// Текст для показа: если флаги нарисовать нечем, 🇩🇪 → «DE».
pub fn text(s: &str) -> String {
    if FLAGS_OK.load(Ordering::Relaxed) {
        s.to_string()
    } else {
        flags_to_codes(s)
    }
}

/// Заменяет флаги (пары Regional Indicator) на буквенные коды стран.
pub fn flags_to_codes(s: &str) -> String {
    if !s.chars().any(|c| regional(c).is_some()) {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        let Some(a) = regional(c) else {
            out.push(c);
            continue;
        };
        out.push(a);
        if let Some(b) = it.peek().copied().and_then(regional) {
            out.push(b);
            it.next();
        }
        // «DE⚡» читается хуже, чем «DE ⚡»
        if it.peek().is_some_and(|n| !n.is_whitespace()) {
            out.push(' ');
        }
    }
    out
}

/// Подключает системный шрифт с флагами. Вызывать после инициализации платформы Slint.
pub fn setup_emoji_flags() {
    use slint::fontique_011::fontique;

    let mut col = slint::fontique_011::shared_collection();
    let root = std::env::var("ANDROID_ROOT").unwrap_or_else(|_| "/system".into());
    let dirs = [format!("{root}/fonts"), "/product/fonts".into(), "/system_ext/fonts".into()];
    let mut flag_families: Vec<fontique::FamilyId> = Vec::new();
    for dir in &dirs {
        let Ok(entries) = std::fs::read_dir(dir) else { continue };
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().to_ascii_lowercase();
            let is_font = name.ends_with(".ttf") || name.ends_with(".otf");
            if !(is_font && name.contains("emoji") && name.contains("flag")) {
                continue;
            }
            let Ok(data) = std::fs::read(e.path()) else { continue };
            let over = fontique::FontInfoOverride { family_name: Some("XrayDroid Emoji Flags"), ..Default::default() };
            for (id, _) in col.register_fonts(fontique::Blob::new(std::sync::Arc::new(data)), Some(over)) {
                if !flag_families.contains(&id) {
                    flag_families.push(id);
                }
            }
            log::info!("шрифт флагов: {}", e.path().display());
        }
    }

    let emoji = fontique::GenericFamily::Emoji;
    if !flag_families.is_empty() {
        // Шрифт флагов — первым: parley берёт его только для кластера, который он покрывает
        // целиком (пара Regional Indicator), остальные эмодзи идут в «Noto Color Emoji».
        // Системные семейства fontique всё равно добавит в конец списка.
        let rest: Vec<_> = col.generic_families(emoji).filter(|f| !flag_families.contains(f)).collect();
        col.set_generic_families(emoji, flag_families.iter().copied().chain(rest));
        for script in [*b"Zsye", *b"Zyyy"] {
            col.append_fallbacks(
                fontique::FallbackKey::new(fontique::Script::from_bytes(script), None),
                flag_families.iter().copied(),
            );
        }
    }

    // есть ли среди шрифтов эмодзи глиф для флага
    let families: Vec<_> = col.generic_families(emoji).collect();
    let mut cache = fontique::SourceCache::default();
    let mut ok = false;
    {
        let mut q = col.query(&mut cache);
        q.set_families(families);
        q.matches_with(|f| {
            if f.charmap().and_then(|c| c.map(0x1F1E9u32)).is_some_and(|g| g != 0) {
                ok = true;
                fontique::QueryStatus::Stop
            } else {
                fontique::QueryStatus::Continue
            }
        });
    }
    FLAGS_OK.store(ok, Ordering::Relaxed);
    if !ok {
        log::warn!("на устройстве нет шрифта с флагами — показываю коды стран");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes() {
        assert_eq!(flags_to_codes("🇩🇪 🎮 ⚡ Германия"), "DE 🎮 ⚡ Германия");
        assert_eq!(flags_to_codes("🇳🇱⚡ LTE"), "NL ⚡ LTE");
        assert_eq!(flags_to_codes("Авто 🇫🇮"), "Авто FI");
        assert_eq!(flags_to_codes("без флага"), "без флага");
    }
}
