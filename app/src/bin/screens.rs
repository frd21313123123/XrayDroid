//! Рендер экранов в PNG без дисплея: `cargo run -p xd-app --bin screens -- out_dir [dark]`
#[cfg(not(target_os = "android"))]
fn main() {
    use slint::platform::software_renderer::{MinimalSoftwareWindow, RepaintBufferType, Rgb565Pixel};
    use slint::platform::{Platform, WindowAdapter};
    use slint::ComponentHandle;
    use std::rc::Rc;
    use std::sync::Arc;
    use xd_core::config::{Profile, Protocol, SplitRoute};

    struct P(Rc<MinimalSoftwareWindow>);
    impl Platform for P {
        fn create_window_adapter(&self) -> Result<Rc<dyn WindowAdapter>, slint::PlatformError> {
            Ok(self.0.clone())
        }
    }
    let out = std::path::PathBuf::from(std::env::args().nth(1).unwrap_or("shots".into()));
    let dark = std::env::args().nth(2).as_deref() == Some("dark");
    std::fs::create_dir_all(&out).unwrap();
    let window = MinimalSoftwareWindow::new(RepaintBufferType::NewBuffer);
    slint::platform::set_platform(Box::new(P(window.clone()))).unwrap();
    // размер макета: 390 × 844
    let (w, h, scale) = (390u32, 844u32, 2.0f32);
    window.dispatch_event(slint::platform::WindowEvent::ScaleFactorChanged { scale_factor: scale });
    window.set_size(slint::PhysicalSize::new((w as f32 * scale) as u32, (h as f32 * scale) as u32));

    // демо-данные как в макете
    let dir = std::env::temp_dir().join("xd_shots");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut cfg = xd_core::AppConfig::default();
    let mk = |id: &str, name: &str, proto: Protocol, net: &str, sec: &str, flow: &str, obfs: &str, ms: i64, sub: &str| Profile {
        id: id.into(),
        remarks: name.into(),
        protocol: proto,
        address: "198.51.100.7".into(),
        port: 443,
        id_or_password: "0a6b0b6f-9e4c-4d0c-9f3a-1f2e3d4c5b6a".into(),
        secret: "pw".into(),
        network: net.into(),
        security: sec.into(),
        flow: flow.into(),
        obfs: obfs.into(),
        method: if proto == Protocol::Shadowsocks { "2022-blake3-aes-128-gcm".into() } else { String::new() },
        public_key: "x".into(),
        delay_ms: ms,
        sub_id: sub.into(),
        ..Default::default()
    };
    cfg.profiles = vec![
        mk("nl", "Нидерланды · Амстердам", Protocol::Vless, "tcp", "reality", "xtls-rprx-vision", "", 48, ""),
        mk("fi", "Финляндия · Хельсинки", Protocol::Hysteria2, "tcp", "tls", "", "salamander", 62, "sub1"),
        mk("de", "Германия · Франкфурт", Protocol::Vless, "xhttp", "tls", "", "", 87, "sub1"),
        mk("kz", "Казахстан · Алматы", Protocol::Trojan, "grpc", "tls", "", "", 164, "sub1"),
        mk("us", "США · Нью-Йорк", Protocol::Tuic, "tcp", "tls", "", "", 312, "sub2"),
        mk("tr", "Турция · Стамбул", Protocol::Shadowsocks, "tcp", "none", "", "", 0, "sub2"),
    ];
    cfg.selected = "nl".into();
    let now = xd_core_now();
    cfg.subscriptions = vec![
        xd_core::Subscription {
            id: "sub1".into(),
            remarks: "[Название подписки]".into(),
            url: "https://sub.example.com/abc123".into(),
            enabled: true,
            last_update: now - 7200,
            used: (34.2 * 1073741824.0) as u64,
            total: 100 * 1073741824,
            expire: now + 33 * 86400,
            custom_name: true,
            ..Default::default()
        },
        xd_core::Subscription {
            id: "sub2".into(),
            remarks: "[Вторая подписка]".into(),
            url: "https://panel.example.net/s/k7…".into(),
            enabled: true,
            last_update: now - 20 * 3600,
            used: 86 * 1073741824,
            total: 100 * 1073741824,
            expire: now + 11 * 86400,
            custom_name: true,
            ..Default::default()
        },
    ];
    for r in cfg.routing.rules.iter_mut() {
        if r.domain.iter().any(|d| d.contains("category-ads")) {
            r.enabled = true;
        }
    }
    cfg.splits = vec![
        SplitRoute {
            id: "s1".into(),
            remarks: "Нейросети".into(),
            enabled: true,
            server: "us".into(),
            apps: vec!["com.openai.chatgpt".into(), "com.google.android.apps.bard".into()],
            domain: vec!["domain:openai.com".into(), "domain:chatgpt.com".into(), "domain:claude.ai".into(), "geosite:google-gemini".into()],
            fallback_main: false,
        },
        SplitRoute {
            id: "s2".into(),
            remarks: "Игры и голос".into(),
            enabled: true,
            server: "fi".into(),
            apps: vec!["com.discord".into(), "com.valvesoftware.android.steam.community".into(), "org.telegram.messenger".into()],
            domain: vec![],
            fallback_main: true,
        },
    ];
    cfg.save(&dir.join("config.json")).unwrap();

    let ui = xraydroid::ui::build(dir.clone(), Arc::new(xraydroid::DesktopHost)).unwrap();
    if dark {
        ui.global::<xraydroid::Theme>().set_dark(true);
    }
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
            let (r, g, b) = (((v >> 11) & 0x1f) as u8, ((v >> 5) & 0x3f) as u8, (v & 0x1f) as u8);
            rgb.push((r << 3) | (r >> 2));
            rgb.push((g << 2) | (g >> 4));
            rgb.push((b << 3) | (b >> 2));
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
    xraydroid::status::on_service(true, "", 1_234_567, 48_765_432, (xd_core_now() - 12 * 60 - 47) * 1000);
    let last = std::cell::RefCell::new(Some((1_000_000u64, 40_000_000u64, std::time::Instant::now() - std::time::Duration::from_secs(1))));
    xraydroid::status::on_service(true, "", 1_310_000, 42_400_000, (xd_core_now() - 12 * 60 - 47) * 1000);
    xraydroid::ui::apply_status(&ui, &last);
    shot("2_main_connected");
    {
        use slint::Model;
        ui.set_sheet_server(ui.get_servers().row_data(1).unwrap());
    }
    ui.set_sheet("server".into());
    shot("2b_server_sheet");
    ui.set_sheet("add".into());
    shot("2c_add_sheet");
    ui.set_sheet("".into());
    ui.invoke_open_page("routing".into());
    shot("3_routing");
    ui.invoke_open_page("subs".into());
    shot("4_subs");
    ui.invoke_open_page("settings".into());
    shot("5_settings");
    ui.invoke_split_open("s1".into());
    shot("6_split");
    ui.invoke_open_page("routing".into());
    let rid = xd_core_first_rule(&dir);
    ui.invoke_rule_open(rid);
    shot("7_rule");
    ui.invoke_edit_server("nl".into());
    shot("8_edit");
    ui.invoke_open_page("settings".into());
    ui.invoke_apps_mode_changed(1);
    ui.invoke_open_page("apps".into());
    ui.set_apps_mode(1);
    shot("9_apps");
    ui.invoke_open_page("advanced".into());
    shot("10_advanced");
    ui.invoke_open_page("about".into());
    shot("11_about");
    // пустая группа: вкладка без загрузки подписки
    ui.invoke_open_page("subs".into());
    ui.invoke_group_new();
    ui.set_sub_name("Мои серверы".into());
    shot("12_group_dialog");
    ui.set_sub_dialog(false);
    ui.invoke_sub_save();
    shot("13_subs_with_group");
    ui.invoke_open_page("main".into());
    shot("14_main_group");
    // обновление приложения: предложение, загрузка, ошибка
    xraydroid::ui::apply_update(&ui, 2, "0.2.0-build.57", "0.2.0-build.42", 0, "", true);
    shot("15_update_dialog");
    ui.set_update_dialog(false);
    ui.invoke_open_page("settings".into());
    shot("16_update_available");
    xraydroid::ui::apply_update(&ui, 3, "0.2.0-build.57", "0.2.0-build.42", 42, "", false);
    shot("17_update_downloading");
    xraydroid::ui::apply_update(&ui, 5, "0.2.0-build.57", "0.2.0-build.42", 0, "Не удалось скачать обновление: HTTP 502", false);
    shot("18_update_error");
}

#[cfg(not(target_os = "android"))]
fn xd_core_now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

#[cfg(not(target_os = "android"))]
fn xd_core_first_rule(dir: &std::path::Path) -> slint::SharedString {
    let cfg = xd_core::AppConfig::load(&dir.join("config.json"));
    cfg.routing.rules[0].id.clone().into()
}

#[cfg(target_os = "android")]
fn main() {}
