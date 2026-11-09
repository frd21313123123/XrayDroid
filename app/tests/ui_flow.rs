//! Сквозная проверка интерфейса без дисплея: клики по окну, лист выбора, долгое нажатие,
//! сохранение маршрута на отдельный сервер.

use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use slint::platform::software_renderer::{MinimalSoftwareWindow, RepaintBufferType};
use slint::platform::{Platform, PointerEventButton, WindowAdapter, WindowEvent};
use slint::{ComponentHandle, LogicalPosition, Model};
use xd_core::config::{Profile, Protocol};

struct P(Rc<MinimalSoftwareWindow>);
impl Platform for P {
    fn create_window_adapter(&self) -> Result<Rc<dyn WindowAdapter>, slint::PlatformError> {
        Ok(self.0.clone())
    }
}

fn profile(id: &str, name: &str, ms: i64) -> Profile {
    Profile {
        id: id.into(),
        remarks: name.into(),
        protocol: Protocol::Trojan,
        address: "198.51.100.7".into(),
        port: 443,
        id_or_password: "pw".into(),
        network: "tcp".into(),
        security: "tls".into(),
        delay_ms: ms,
        ..Default::default()
    }
}

#[test]
fn ui_flow() {
    let window = MinimalSoftwareWindow::new(RepaintBufferType::NewBuffer);
    slint::platform::set_platform(Box::new(P(window.clone()))).unwrap();
    window.dispatch_event(WindowEvent::ScaleFactorChanged { scale_factor: 1.0 });
    window.set_size(slint::PhysicalSize::new(390, 844));

    let dir = std::env::temp_dir().join(format!("xd_ui_flow_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut cfg = xd_core::AppConfig::default();
    cfg.profiles = vec![profile("a", "Алма", 40), profile("b", "Берлин", 90), profile("c", "Вена", 300)];
    cfg.selected = "a".into();
    cfg.save(&dir.join("config.json")).unwrap();

    let ui = xraydroid::ui::build(dir.clone(), Arc::new(xraydroid::DesktopHost)).unwrap();
    ui.show().unwrap();

    let pump = |ms: u64| {
        slint::platform::update_timers_and_animations();
        if ms > 0 {
            std::thread::sleep(Duration::from_millis(ms));
            slint::platform::update_timers_and_animations();
        }
    };
    let press = |x: f32, y: f32| {
        let position = LogicalPosition::new(x, y);
        window.dispatch_event(WindowEvent::PointerMoved { position });
        window.dispatch_event(WindowEvent::PointerPressed { position, button: PointerEventButton::Left });
    };
    let release = |x: f32, y: f32| {
        window.dispatch_event(WindowEvent::PointerReleased { position: LogicalPosition::new(x, y), button: PointerEventButton::Left });
    };
    let click = |x: f32, y: f32| {
        press(x, y);
        release(x, y);
        pump(0);
    };
    pump(50);

    // ── список серверов: статус и задержки ──
    let servers = ui.get_servers();
    assert_eq!(servers.row_count(), 3);
    assert_eq!(servers.row_data(0).unwrap().delay_state, 1);
    assert_eq!(servers.row_data(2).unwrap().delay_state, 3);
    assert_eq!(ui.get_groups().row_data(0).unwrap().as_str(), "Все · 3");

    // ── вкладка «Маршруты»: выбор стратегии DNS через нижний лист ──
    ui.invoke_open_page("routing".into());
    pump(50);
    assert_eq!(ui.get_strategy_index(), 1);
    click(200.0, 159.0); // строка «Стратегия DNS»
    assert!(ui.global::<xraydroid::Picker>().get_visible(), "лист выбора должен открыться");
    assert_eq!(ui.global::<xraydroid::Picker>().get_current(), 1);
    // лист снизу: 3 строки по 52 px, нижняя — «IPOnDemand»
    let sheet_h = 10.0 + 4.0 + 48.0 + 156.0 + 12.0;
    let third_row = 844.0 - sheet_h + 62.0 + 52.0 * 2.0 + 26.0;
    click(200.0, third_row);
    assert!(!ui.global::<xraydroid::Picker>().get_visible());
    assert_eq!(ui.get_strategy_index(), 2, "выбор из листа дошёл до окна");
    let saved = xd_core::AppConfig::load(&dir.join("config.json"));
    assert_eq!(saved.routing.domain_strategy, "IPOnDemand");

    // ── маршрут на отдельный сервер: создание ──
    ui.invoke_split_open("".into());
    pump(50);
    assert_eq!(ui.get_page().as_str(), "split");
    assert_eq!(ui.get_split_servers().row_count(), 3);
    ui.invoke_split_save(); // ничего не выбрано
    assert_eq!(ui.get_page().as_str(), "split", "без сервера сохранять нельзя");
    let mut f = ui.get_split_form();
    f.name = "Нейросети".into();
    f.domain = "domain:openai.com\nkeyword:gemini".into();
    ui.set_split_form(f);
    ui.invoke_split_pick_server("b".into());
    assert!(ui.get_split_servers().iter().any(|s| s.id == "b" && s.selected));
    ui.invoke_split_app_toggle("com.discord".into(), true);
    assert_eq!(ui.get_split_apps_count(), 1);
    ui.invoke_split_filter_changed("tele".into());
    assert_eq!(ui.get_split_apps().row_count(), 1);
    ui.invoke_split_filter_changed("".into());
    ui.invoke_split_save();
    assert_eq!(ui.get_page().as_str(), "routing");
    let saved = xd_core::AppConfig::load(&dir.join("config.json"));
    assert_eq!(saved.splits.len(), 1);
    let sp = &saved.splits[0];
    assert_eq!((sp.server.as_str(), sp.apps.as_slice(), sp.domain.len(), sp.enabled), ("b", &["com.discord".to_string()][..], 2, true));
    assert_eq!(ui.get_splits().row_count(), 1);
    assert_eq!(ui.get_splits().row_data(0).unwrap().server.as_str(), "Берлин");

    // выключение и удаление
    ui.invoke_split_toggle(sp.id.clone().into(), false);
    assert!(!xd_core::AppConfig::load(&dir.join("config.json")).splits[0].enabled);
    ui.invoke_confirm_ok(format!("delete-split:{}", sp.id).into());
    assert!(xd_core::AppConfig::load(&dir.join("config.json")).splits.is_empty());

    // ── главный экран: короткое нажатие выбирает, долгое открывает меню ──
    ui.invoke_open_page("main".into());
    pump(50);
    // Находим строки списка кликами. Базовый выбор — «a» (раскладка с «пилюлей» сервера не меняется):
    // клик по второй строке даёт «b», по третьей — «c».
    let selected_idx = || (0..3).find(|i| ui.get_servers().row_data(*i).unwrap().selected);
    let mut starts: [Option<f32>; 3] = [None; 3];
    let mut y = 150.0;
    while y < 700.0 {
        ui.invoke_select_server("a".into());
        click(200.0, y);
        if let Some(i @ 1..=2) = selected_idx() {
            starts[i].get_or_insert(y);
        }
        y += 2.0;
    }
    let (r1, r2) = (starts[1].expect("строка 2"), starts[2].expect("строка 3"));
    assert!((r2 - r1 - 64.0).abs() <= 2.0, "строки по 64 px: {r1} {r2}");

    // короткое нажатие на «Вена» выбирает сервер
    ui.invoke_select_server("a".into());
    click(200.0, r2 + 32.0);
    assert_eq!(selected_idx(), Some(2), "короткое нажатие выбирает сервер");
    // долгое нажатие на «Берлин» открывает меню и не меняет выбор
    press(200.0, r1 + 32.0);
    pump(600);
    release(200.0, r1 + 32.0);
    pump(0);
    assert_eq!(ui.get_sheet().as_str(), "server");
    assert_eq!(ui.get_sheet_id().as_str(), "b");
    assert_eq!(selected_idx(), Some(2), "долгое нажатие не меняет выбор");
    ui.set_sheet("".into());

    // ── статус ──
    xraydroid::status::on_service(true, "", 10, 20, 0);
    xraydroid::ui::apply_status(&ui, &std::cell::RefCell::new(None));
    assert_eq!(ui.get_status_title().as_str(), "Защищено");
    assert!(ui.get_running());
    xraydroid::status::on_service(false, "порт занят", 0, 0, 0);
    xraydroid::ui::apply_status(&ui, &std::cell::RefCell::new(None));
    assert_eq!(ui.get_status_title().as_str(), "Ошибка");
    assert!(ui.get_status_error());

    let _ = std::fs::remove_dir_all(&dir);
}
