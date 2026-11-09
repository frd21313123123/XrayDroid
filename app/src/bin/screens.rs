//! Рендер экранов в PNG без дисплея: `cargo run -p xd-app --bin screens -- out_dir`
#[cfg(not(target_os = "android"))]
fn main() {
    use slint::platform::software_renderer::{MinimalSoftwareWindow, RepaintBufferType, Rgb565Pixel};
    use slint::platform::{Platform, WindowAdapter};
    use slint::ComponentHandle;
    use std::rc::Rc;
    use std::sync::Arc;

    struct P(Rc<MinimalSoftwareWindow>);
    impl Platform for P {
        fn create_window_adapter(&self) -> Result<Rc<dyn WindowAdapter>, slint::PlatformError> {
            Ok(self.0.clone())
        }
    }
    let out = std::path::PathBuf::from(std::env::args().nth(1).unwrap_or("shots".into()));
    std::fs::create_dir_all(&out).unwrap();
    let window = MinimalSoftwareWindow::new(RepaintBufferType::NewBuffer);
    slint::platform::set_platform(Box::new(P(window.clone()))).unwrap();
    let (w, h, scale) = (412u32, 860u32, 2.0f32);
    window.dispatch_event(slint::platform::WindowEvent::ScaleFactorChanged { scale_factor: scale });
    window.set_size(slint::PhysicalSize::new((w as f32 * scale) as u32, (h as f32 * scale) as u32));

    // демо-данные
    let dir = std::env::temp_dir().join("xd_shots");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut cfg = xd_core::AppConfig::default();
    let links = [
        "vless://0a6b0b6f-9e4c-4d0c-9f3a-1f2e3d4c5b6a@91.107.12.34:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&pbk=8P0YgBPvNVh4ozH_v7_Jl9Uafe2CNLtWQbLwghwKRg0&sid=6ba8&type=tcp#🇩🇪 Германия · Франкфурт",
        "vless://0a6b0b6f-9e4c-4d0c-9f3a-1f2e3d4c5b6a@nl1.example-vpn.net:443?encryption=none&security=reality&sni=www.apple.com&pbk=8P0YgBPvNVh4ozH_v7_Jl9Uafe2CNLtWQbLwghwKRg0&type=tcp#🇳🇱 Нидерланды",
        "trojan://pass@fi.example-vpn.net:443?security=tls&type=ws&path=%2Fws#🇫🇮 Финляндия",
        "ss://YWVzLTI1Ni1nY206cGFzcw@45.12.200.7:8388#🇰🇿 Казахстан",
        "vmess://eyJ2IjoiMiIsInBzIjoi8J+HuvCfh7gg0KHQqNCQIiwiYWRkIjoidXMuZXhhbXBsZS5jb20iLCJwb3J0IjoiNDQzIiwiaWQiOiIwYTZiMGI2Zi05ZTRjLTRkMGMtOWYzYS0xZjJlM2Q0YzViNmEiLCJuZXQiOiJ3cyIsInRscyI6InRscyJ9",
    ];
    for (i, l) in links.iter().enumerate() {
        let mut p = xd_core::links::parse_link(l).unwrap();
        p.delay_ms = [87, 143, 512, -1, 0][i];
        if i >= 2 {
            p.sub_id = "sub1".into();
        }
        cfg.profiles.push(p);
    }
    cfg.selected = cfg.profiles[0].id.clone();
    cfg.subscriptions.push(xd_core::Subscription {
        id: "sub1".into(),
        remarks: "Мой провайдер".into(),
        url: "https://sub.example.com/api/v1/client/subscribe?token=abc".into(),
        enabled: true,
        last_update: xd_core_now() - 7200,
        info: "трафик 12.4 ГБ из 100.0 ГБ · осталось 23 дн".into(),
        custom_name: true,
    });
    cfg.save(&dir.join("config.json")).unwrap();

    let ui = xraydroid::ui::build(dir.clone(), Arc::new(xraydroid::DesktopHost)).unwrap();
    ui.show().unwrap();

    let shot = |name: &str| {
        slint::platform::update_timers_and_animations();
        std::thread::sleep(std::time::Duration::from_millis(300));
        slint::platform::update_timers_and_animations();
        let (pw, ph) = ((w as f32 * scale) as u32, (h as f32 * scale) as u32);
        let mut buf = vec![Rgb565Pixel(0); (pw * ph) as usize];
        window.request_redraw();
        window.draw_if_needed(|r| {
            r.render(&mut buf, pw as usize);
        });
        let mut rgb = Vec::with_capacity((pw * ph * 3) as usize);
        for p in &buf {
            let v = p.0;
            rgb.push((((v >> 11) & 0x1f) << 3) as u8);
            rgb.push((((v >> 5) & 0x3f) << 2) as u8);
            rgb.push(((v & 0x1f) << 3) as u8);
        }
        let f = std::fs::File::create(out.join(format!("{name}.png"))).unwrap();
        let mut e = png::Encoder::new(std::io::BufWriter::new(f), pw, ph);
        e.set_color(png::ColorType::Rgb);
        e.set_depth(png::BitDepth::Eight);
        e.write_header().unwrap().write_image_data(&rgb).unwrap();
        println!("{name}.png");
    };

    shot("1_main");
    ui.invoke_toggle_vpn();
    xraydroid::status::on_service(true, "", 1_234_567, 48_765_432);
    xraydroid::ui::apply_status(&ui, &std::cell::RefCell::new(None));
    shot("2_main_connected");
    ui.set_current_group(1);
    ui.invoke_group_changed(2);
    shot("3_main_group");
    ui.invoke_group_changed(0);
    ui.set_drawer_open(true);
    shot("4_drawer");
    ui.set_drawer_open(false);
    slint::platform::update_timers_and_animations();
    ui.invoke_edit_server(ui.get_servers().row_data_opt(0).unwrap().id);
    shot("5_edit");
    ui.invoke_open_page("routing".into());
    shot("6_routing");
    ui.invoke_rule_open(xd_core_first_rule(&dir));
    shot("7_rule");
    ui.invoke_open_page("subs".into());
    shot("8_subs");
    ui.invoke_open_page("settings".into());
    shot("9_settings");
    ui.invoke_open_page("apps".into());
    ui.invoke_apps_mode_changed(1);
    ui.set_apps_mode(1);
    shot("10_apps");
}

#[cfg(not(target_os = "android"))]
fn xd_core_now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

#[cfg(not(target_os = "android"))]
fn xd_core_first_rule(dir: &std::path::Path) -> slint::SharedString {
    let cfg = xd_core::AppConfig::load(&dir.join("config.json"));
    cfg.routing.rules[3].id.clone().into()
}

#[cfg(target_os = "android")]
fn main() {}

#[cfg(not(target_os = "android"))]
trait RowOpt<T> {
    fn row_data_opt(&self, i: usize) -> Option<T>;
}
#[cfg(not(target_os = "android"))]
impl<T: Clone + 'static> RowOpt<T> for slint::ModelRc<T> {
    fn row_data_opt(&self, i: usize) -> Option<T> {
        use slint::Model;
        self.row_data(i)
    }
}
