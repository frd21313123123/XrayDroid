//! Связка интерфейса с логикой.

use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use slint::{ComponentHandle, SharedString, Timer, TimerMode, Weak};
use xd_core::config::{OutboundTag, Profile, Subscription};
use xd_core::route::presets::{apply_preset, PRESETS};

use crate::state::{self, model, State};
use crate::{status, Host, MainWindow, SplitForm};

type S = Rc<RefCell<State>>;

pub fn fmt_bytes(b: f64) -> String {
    if b < 1024.0 {
        format!("{b:.0} Б")
    } else if b < 1048576.0 {
        format!("{:.1} КБ", b / 1024.0)
    } else if b < 1073741824.0 {
        format!("{:.1} МБ", b / 1048576.0)
    } else {
        format!("{:.2} ГБ", b / 1073741824.0)
    }
}

/// Скорость для плитки: («2,4», «МБ/с»).
pub fn speed_parts(bps: f64) -> (String, String) {
    let ru = |v: f64, digits: usize| format!("{v:.digits$}").replace('.', ",");
    if bps < 1024.0 {
        (ru(bps, 0), "Б/с".into())
    } else if bps < 1024.0 * 1024.0 {
        let v = bps / 1024.0;
        (ru(v, if v >= 100.0 { 0 } else { 1 }), "КБ/с".into())
    } else {
        let v = bps / 1048576.0;
        (ru(v, if v >= 100.0 { 0 } else { 1 }), "МБ/с".into())
    }
}

fn fmt_uptime(secs: i64) -> String {
    let s = secs.max(0);
    format!("{:02}:{:02}:{:02}", s / 3600, s % 3600 / 60, s % 60)
}

fn toast(ui: &MainWindow, text: &str) {
    ui.set_toast_text(text.into());
    ui.set_toast_visible(true);
    let w = ui.as_weak();
    let t = text.to_string();
    Timer::single_shot(Duration::from_millis(2800), move || {
        if let Some(ui) = w.upgrade() {
            if ui.get_toast_text() == t.as_str() {
                ui.set_toast_visible(false);
            }
        }
    });
}

fn refresh_servers(ui: &MainWindow, st: &State) {
    let groups = st.groups();
    let idx = groups.iter().position(|(id, _)| *id == st.group).unwrap_or(0);
    ui.set_groups(state::strings(groups.into_iter().map(|g| g.1).collect()));
    ui.set_current_group(idx as i32);
    ui.set_servers(model(st.server_items()));
    ui.set_selected_name(st.cfg.selected_profile().map(|p| crate::fonts::text(&p.display_name())).unwrap_or_default().into());
}

fn refresh_routing(ui: &MainWindow, st: &State) {
    ui.set_rules(model(st.rule_items()));
    ui.set_strategy_index(match st.cfg.routing.domain_strategy.as_str() {
        "AsIs" => 0,
        "IPOnDemand" => 2,
        _ => 1,
    });
    ui.set_final_index(st.cfg.routing.final_outbound.index());
    ui.set_preset_index(PRESETS.iter().position(|(id, _)| *id == st.cfg.routing.preset).unwrap_or(0) as i32);
    ui.set_splits(model(st.split_items()));
    ui.set_geo_status(st.geo_status().into());
}

fn refresh_split_servers(ui: &MainWindow, st: &State) {
    ui.set_split_servers(model(st.split_server_items()));
    ui.set_split_server(st.split_server_item());
}

fn refresh_split_apps(ui: &MainWindow, st: &State) {
    let (items, more) = st.split_app_items();
    ui.set_split_apps_count(st.split_apps.len() as i32);
    ui.set_split_apps(model(items));
    ui.set_split_apps_more(more.into());
}

fn refresh_apps(ui: &MainWindow, st: &State) {
    let (items, more) = st.app_items();
    ui.set_apps(model(items));
    ui.set_apps_more(more.into());
}

/// Перезапуск VPN, если он запущен (после смены сервера/настроек).
fn restart_if_running(host: &Arc<dyn Host>) {
    if status::get().running {
        status::set_connecting();
        host.start_vpn();
    }
}

/// Добавление профилей из текста; ссылка http(s) — это подписка.
fn import_text(ui: &MainWindow, st: &S, host: &Arc<dyn Host>, text: &str) {
    let text = text.trim();
    if text.is_empty() {
        toast(ui, "Буфер обмена пуст");
        return;
    }
    if (text.starts_with("http://") || text.starts_with("https://")) && !text.contains('\n') {
        let id = Profile::new_id();
        {
            let mut s = st.borrow_mut();
            let n = s.cfg.subscriptions.len() + 1;
            s.cfg.subscriptions.push(Subscription {
                id: id.clone(),
                remarks: format!("Подписка {n}"),
                url: text.to_string(),
                enabled: true,
                ..Default::default()
            });
            s.save();
        }
        toast(ui, "Подписка добавлена, обновляю…");
        update_subs(ui, st, host, Some(id));
        return;
    }
    let list = xd_core::links::parse_many(text);
    if list.is_empty() {
        toast(ui, "Не найдено поддерживаемых ссылок");
        return;
    }
    let n = list.len();
    {
        let mut s = st.borrow_mut();
        let mut list = list;
        // открыта вкладка группы без ссылки — серверы попадают в неё
        let local = s.local_group();
        if let Some(g) = &local {
            for p in &mut list {
                p.sub_id = g.clone();
            }
        }
        let first = list[0].id.clone();
        s.cfg.profiles.extend(list);
        if s.cfg.selected_profile().is_none() {
            s.cfg.selected = first;
        }
        if local.is_none() && s.group != "" && s.group != "manual" {
            s.group = String::new();
        }
        s.save();
        refresh_servers(ui, &s);
    }
    toast(ui, &format!("Импортировано серверов: {n}"));
}

fn update_subs(ui: &MainWindow, st: &S, _host: &Arc<dyn Host>, only: Option<String>) {
    let (subs, ua): (Vec<Subscription>, String) = {
        let s = st.borrow();
        (
            s.cfg
                .subscriptions
                .iter()
                .filter(|x| x.enabled && !x.url.trim().is_empty() && only.as_ref().map(|o| *o == x.id).unwrap_or(true))
                .cloned()
                .collect(),
            s.cfg.settings.sub_user_agent.clone(),
        )
    };
    if subs.is_empty() {
        toast(ui, "Нет включённых подписок");
        return;
    }
    ui.set_subs_busy(true);
    let w = ui.as_weak();
    std::thread::spawn(move || {
        let mut results = Vec::new();
        for s in subs {
            let r = xd_core::subscription::update(&s, &ua);
            if let Err(e) = &r {
                log::warn!("подписка {}: {e}", s.url);
            }
            results.push((s.id.clone(), s.remarks.clone(), r.map_err(|e| e.to_string())));
        }
        let _ = w.upgrade_in_event_loop(move |ui| {
            ui.set_subs_busy(false);
            with_state(|st| {
                let mut ok = 0;
                let mut errors = Vec::new();
                {
                    let mut s = st.borrow_mut();
                    for (id, name, r) in results {
                        match r {
                            Ok(upd) => {
                                let mut list = upd.profiles;
                                // сохраняем выбор, если сервер остался
                                let sel = s.cfg.selected_profile().filter(|p| p.sub_id == id).map(state::dedup_key);
                                s.cfg.profiles.retain(|p| p.sub_id != id);
                                for p in &mut list {
                                    if Some(state::dedup_key(p)) == sel {
                                        s.cfg.selected = p.id.clone();
                                    }
                                }
                                ok += list.len();
                                s.cfg.profiles.extend(list);
                                if let Some(sub) = s.cfg.subscriptions.iter_mut().find(|x| x.id == id) {
                                    sub.last_update = state::now_secs();
                                    sub.info = upd.info;
                                    sub.used = upd.usage.used;
                                    sub.total = upd.usage.total;
                                    sub.expire = upd.usage.expire;
                                    if let (Some(t), false) = (upd.title, sub.custom_name) {
                                        sub.remarks = t;
                                    }
                                }
                            }
                            Err(e) => errors.push(format!("{name}: {e}")),
                        }
                    }
                    if s.cfg.selected_profile().is_none() {
                        s.cfg.selected = s.cfg.profiles.first().map(|p| p.id.clone()).unwrap_or_default();
                    }
                    s.save();
                    refresh_servers(&ui, &s);
                    ui.set_subs(model(s.sub_items()));
                }
                if errors.is_empty() {
                    toast(&ui, &format!("Подписки обновлены, серверов: {ok}"));
                } else {
                    toast(&ui, &format!("Ошибка: {}", errors.join("; ")));
                }
            });
        });
    });
}

thread_local! {
    static STATE: RefCell<Option<S>> = const { RefCell::new(None) };
}

fn with_state(f: impl FnOnce(&S)) {
    STATE.with(|s| {
        if let Some(st) = s.borrow().as_ref() {
            f(st)
        }
    });
}

/// Одновременных проверок задержки.
const DELAY_PARALLEL: usize = 10;
/// Жёсткий предел на одну проверку: что бы ни случилось в ядре, сервер получит результат.
const DELAY_HARD_LIMIT: Duration = Duration::from_secs(20);

fn run_delay_tests(ui: &MainWindow, st: &S, ids: Vec<String>) {
    let (profiles, url) = {
        let mut s = st.borrow_mut();
        let want: std::collections::HashSet<&str> = ids.iter().map(String::as_str).collect();
        // серверы, которые уже проверяются, повторно не запускаем
        let ps: Vec<Profile> = s
            .cfg
            .profiles
            .iter()
            .filter(|p| want.contains(p.id.as_str()) && !s.testing.contains(&p.id))
            .cloned()
            .collect();
        for p in &ps {
            s.testing.insert(p.id.clone());
        }
        refresh_servers(ui, &s);
        (ps, s.cfg.settings.test_url.clone())
    };
    let total = profiles.len();
    if total == 0 {
        return;
    }
    let w = ui.as_weak();
    let rt = xd_core::engine::shared_runtime();
    let sem = Arc::new(tokio::sync::Semaphore::new(DELAY_PARALLEL));
    let done = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let ok = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    for p in profiles {
        let w = w.clone();
        let url = url.clone();
        let sem = sem.clone();
        let done = done.clone();
        let ok = ok.clone();
        rt.spawn(async move {
            let _permit = sem.acquire_owned().await;
            let id = p.id.clone();
            let name = p.display_name();
            // отдельная задача: паника или зависание в ядре не оставят сервер в состоянии «…»
            let job = tokio::spawn(async move { xd_core::engine::delay_test(&p, &url).await });
            let abort = job.abort_handle();
            let r = match tokio::time::timeout(DELAY_HARD_LIMIT, job).await {
                Ok(Ok(r)) => r,
                Ok(Err(e)) => Err(std::io::Error::other(format!("сбой проверки: {e}"))),
                Err(_) => {
                    abort.abort();
                    Err(std::io::Error::other("таймаут"))
                }
            };
            if let Err(e) = &r {
                log::info!("тест {name}: {e}");
            }
            let ms = r.map(|d| d as i64).unwrap_or(-1);
            if ms > 0 {
                ok.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            let n = done.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
            let good = ok.load(std::sync::atomic::Ordering::SeqCst);
            let _ = w.upgrade_in_event_loop(move |ui| {
                with_state(|st| {
                    let mut s = st.borrow_mut();
                    s.testing.remove(&id);
                    if let Some(p) = s.cfg.profiles.iter_mut().find(|p| p.id == id) {
                        p.delay_ms = ms;
                    }
                    // сохраняем по ходу, чтобы результаты не терялись
                    if s.testing.is_empty() || n % 25 == 0 || n == total {
                        s.save();
                    }
                    update_server_row(&ui, &s, &id);
                    if n == total && total > 1 {
                        toast(&ui, &format!("Проверено серверов: {total}, отвечают: {good}"));
                    }
                });
            });
        });
    }
}

/// Обновляет одну строку списка серверов, не пересоздавая весь список (позиция прокрутки сохраняется).
fn update_server_row(ui: &MainWindow, st: &State, id: &str) {
    use slint::Model;
    let Some(p) = st.cfg.profiles.iter().find(|p| p.id == id) else { return };
    let item = st.server_item(p, p.id == st.cfg.selected);
    let m = ui.get_servers();
    for i in 0..m.row_count() {
        if m.row_data(i).is_some_and(|r| r.id.as_str() == id) {
            m.set_row_data(i, item);
            return;
        }
    }
}

fn load_apps(ui: &MainWindow, st: &S, host: &Arc<dyn Host>) {
    if st.borrow().apps_loaded {
        refresh_apps(ui, &st.borrow());
        refresh_split_apps(ui, &st.borrow());
        return;
    }
    // на десктопе (скриншоты) список отдаётся мгновенно
    #[cfg(not(target_os = "android"))]
    {
        let mut s = st.borrow_mut();
        s.apps = host.installed_apps();
        s.apps_loaded = true;
        refresh_apps(ui, &s);
        refresh_split_apps(ui, &s);
        ui.set_splits(model(s.split_items()));
        return;
    }
    #[allow(unreachable_code)]
    {
    ui.set_apps_loading(true);
    let w = ui.as_weak();
    let host = host.clone();
    std::thread::spawn(move || {
        let apps = host.installed_apps();
        let _ = w.upgrade_in_event_loop(move |ui| {
            with_state(|st| {
                let mut s = st.borrow_mut();
                s.apps = apps;
                s.apps_loaded = true;
                refresh_apps(&ui, &s);
                refresh_split_apps(&ui, &s);
                ui.set_splits(model(s.split_items()));
                ui.set_apps_loading(false);
            });
        });
    });
    }
}

pub fn build(dir: PathBuf, host: Arc<dyn Host>) -> Result<MainWindow, slint::PlatformError> {
    let ui = MainWindow::new()?;
    let st: S = Rc::new(RefCell::new(State::load(&dir)));
    STATE.with(|s| *s.borrow_mut() = Some(st.clone()));

    ui.set_version(env!("CARGO_PKG_VERSION").into());
    ui.set_presets(state::strings(PRESETS.iter().map(|(_, n)| n.to_string()).collect()));
    refresh_servers(&ui, &st.borrow());
    ui.invoke_focus_keys();

    // ── статус VPN: опрос раз в секунду ──
    {
        let w = ui.as_weak();
        let timer = Timer::default();
        let last: RefCell<Option<(u64, u64, std::time::Instant)>> = RefCell::new(None);
        timer.start(TimerMode::Repeated, Duration::from_millis(1000), move || {
            let Some(ui) = w.upgrade() else { return };
            apply_status(&ui, &last);
        });
        std::mem::forget(timer);
    }

    // ── главный экран ──
    {
        let h = host.clone();
        let s = st.clone();
        let w = ui.as_weak();
        ui.on_toggle_vpn(move || {
            let ui = w.unwrap();
            let stt = status::get();
            if stt.running || stt.connecting {
                status::set_stopping();
                h.stop_vpn();
            } else {
                let has = s.borrow().cfg.selected_profile().is_some();
                if !has {
                    toast(&ui, "Сначала выберите сервер");
                    return;
                }
                s.borrow().save();
                status::set_connecting();
                h.start_vpn();
            }
            apply_status(&ui, &RefCell::new(None));
        });
    }
    {
        let s = st.clone();
        let w = ui.as_weak();
        ui.on_test_all(move || {
            let ui = w.unwrap();
            let ids = s.borrow().group_ids();
            if ids.is_empty() {
                toast(&ui, "Нет серверов для проверки");
            } else {
                run_delay_tests(&ui, &s, ids);
            }
        });
    }
    {
        let s = st.clone();
        let w = ui.as_weak();
        ui.on_test_server(move |id| run_delay_tests(&w.unwrap(), &s, vec![id.to_string()]));
    }
    {
        let s = st.clone();
        let h = host.clone();
        let w = ui.as_weak();
        ui.on_select_server(move |id| {
            let ui = w.unwrap();
            let changed = {
                let mut st = s.borrow_mut();
                let changed = st.cfg.selected != id.as_str();
                st.cfg.selected = id.to_string();
                st.save();
                refresh_servers(&ui, &st);
                changed
            };
            if changed {
                restart_if_running(&h);
            }
        });
    }
    {
        // «Подключиться» в листе сервера: выбрать его и включить VPN, если он выключен
        let w = ui.as_weak();
        ui.on_connect_server(move |id| {
            let ui = w.unwrap();
            ui.invoke_select_server(id);
            let stt = status::get();
            if !stt.running && !stt.connecting {
                ui.invoke_toggle_vpn();
            }
        });
    }
    {
        let s = st.clone();
        let w = ui.as_weak();
        ui.on_edit_server(move |id| {
            let ui = w.unwrap();
            if let Some(p) = s.borrow().cfg.profiles.iter().find(|p| p.id == id.as_str()) {
                ui.set_form(state::profile_to_form(p));
                ui.set_form_is_new(false);
                ui.set_page("edit".into());
            }
        });
    }
    {
        let s = st.clone();
        let h = host.clone();
        let w = ui.as_weak();
        ui.on_share_server(move |id| {
            let ui = w.unwrap();
            if let Some(p) = s.borrow().cfg.profiles.iter().find(|p| p.id == id.as_str()) {
                h.set_clipboard(&xd_core::links::to_link(p));
                toast(&ui, "Ссылка скопирована в буфер обмена");
            }
        });
    }
    {
        let s = st.clone();
        let w = ui.as_weak();
        ui.on_add_manual(move |proto| {
            let ui = w.unwrap();
            ui.set_form(state::new_form(proto, s.borrow().cfg.settings.allow_insecure_default));
            ui.set_form_is_new(true);
            ui.set_page("edit".into());
        });
    }
    {
        let s = st.clone();
        let h = host.clone();
        let w = ui.as_weak();
        ui.on_import_clipboard(move || {
            let ui = w.unwrap();
            match h.get_clipboard() {
                Some(t) => import_text(&ui, &s, &h, &t),
                None => {
                    ui.set_paste_text(SharedString::new());
                    ui.set_paste_visible(true);
                }
            }
        });
    }
    {
        let s = st.clone();
        let h = host.clone();
        let w = ui.as_weak();
        ui.on_import_text(move |t| import_text(&w.unwrap(), &s, &h, &t));
    }
    {
        let s = st.clone();
        let w = ui.as_weak();
        ui.on_group_changed(move |i| {
            let ui = w.unwrap();
            let mut st = s.borrow_mut();
            let groups = st.groups();
            st.group = groups.get(i as usize).map(|g| g.0.clone()).unwrap_or_default();
            refresh_servers(&ui, &st);
        });
    }
    {
        let s = st.clone();
        let h = host.clone();
        let w = ui.as_weak();
        ui.on_menu_action(move |a| {
            let ui = w.unwrap();
            match a.as_str() {
                "test-all" => {
                    let ids = s.borrow().group_ids();
                    if ids.is_empty() {
                        toast(&ui, "Нет серверов для проверки");
                    } else {
                        run_delay_tests(&ui, &s, ids);
                    }
                }
                "sort" => {
                    let mut st = s.borrow_mut();
                    let key = |d: i64| if d > 0 { d } else if d == 0 { i64::MAX - 1 } else { i64::MAX };
                    st.cfg.profiles.sort_by_key(|p| key(p.delay_ms));
                    st.save();
                    refresh_servers(&ui, &st);
                }
                "update-subs" => update_subs(&ui, &s, &h, None),
                "export" => {
                    let st = s.borrow();
                    let links: Vec<String> =
                        st.cfg.profiles.iter().filter(|p| st.in_group(p)).map(xd_core::links::to_link).collect();
                    h.set_clipboard(&links.join("\n"));
                    toast(&ui, &format!("Скопировано ссылок: {}", links.len()));
                }
                "dedup" => {
                    let mut st = s.borrow_mut();
                    let before = st.cfg.profiles.len();
                    let mut seen = std::collections::HashSet::new();
                    st.cfg.profiles.retain(|p| seen.insert(state::dedup_key(p)));
                    let n = before - st.cfg.profiles.len();
                    st.save();
                    refresh_servers(&ui, &st);
                    toast(&ui, &format!("Удалено дубликатов: {n}"));
                }
                "remove-bad" => {
                    let mut st = s.borrow_mut();
                    let before = st.cfg.profiles.len();
                    let g = st.group.clone();
                    let sel = st.cfg.selected.clone();
                    st.cfg.profiles.retain(|p| {
                        let in_g = g.is_empty() || (g == "manual" && p.sub_id.is_empty()) || p.sub_id == g;
                        !(in_g && p.delay_ms < 0 && p.id != sel)
                    });
                    let n = before - st.cfg.profiles.len();
                    st.save();
                    refresh_servers(&ui, &st);
                    toast(&ui, &format!("Удалено недоступных: {n}"));
                }
                _ => {}
            }
        });
    }
    {
        let s = st.clone();
        let h = host.clone();
        let w = ui.as_weak();
        ui.on_open_page(move |p| {
            let ui = w.unwrap();
            {
                let st = s.borrow();
                match p.as_str() {
                    "main" => refresh_servers(&ui, &st),
                    "subs" => {
                        ui.set_subs(model(st.sub_items()));
                        ui.set_sub_auto(st.cfg.settings.sub_auto_update);
                    }
                    "routing" => refresh_routing(&ui, &st),
                    "settings" => {
                        ui.set_settings(state::settings_to_form(&st.cfg.settings));
                        ui.set_apps_summary(st.apps_summary().into());
                    }
                    "advanced" => ui.set_settings(state::settings_to_form(&st.cfg.settings)),
                    "apps" => ui.set_apps_mode(st.cfg.settings.per_app_mode),
                    "logs" => ui.set_logs(state::strings(xd_core::logbuf::tail_file(400))),
                    _ => {}
                }
            }
            if p.as_str() == "apps" && s.borrow().cfg.settings.per_app_mode != 0 {
                load_apps(&ui, &s, &h);
            }
            // названия приложений для значков в списке отдельных серверов
            if p.as_str() == "routing" && s.borrow().cfg.splits.iter().any(|x| !x.apps.is_empty()) {
                load_apps(&ui, &s, &h);
            }
            ui.set_page(p);
            ui.invoke_focus_keys();
        });
    }
    {
        let s = st.clone();
        let h = host.clone();
        let w = ui.as_weak();
        ui.on_confirm_ok(move |action| {
            let ui = w.unwrap();
            let action = action.to_string();
            let (kind, arg) = action.split_once(':').unwrap_or((action.as_str(), ""));
            let mut st = s.borrow_mut();
            match kind {
                "delete-server" => {
                    st.cfg.profiles.retain(|p| p.id != arg);
                    if st.cfg.selected == arg {
                        st.cfg.selected = st.cfg.profiles.first().map(|p| p.id.clone()).unwrap_or_default();
                    }
                    st.save();
                    refresh_servers(&ui, &st);
                }
                "delete-group" => {
                    let g = st.group.clone();
                    st.cfg.profiles.retain(|p| !(g.is_empty() || (g == "manual" && p.sub_id.is_empty()) || p.sub_id == g));
                    if st.cfg.selected_profile().is_none() {
                        st.cfg.selected = st.cfg.profiles.first().map(|p| p.id.clone()).unwrap_or_default();
                    }
                    st.save();
                    refresh_servers(&ui, &st);
                }
                "delete-sub" => {
                    st.cfg.subscriptions.retain(|x| x.id != arg);
                    st.cfg.profiles.retain(|p| p.sub_id != arg);
                    if st.group == arg {
                        st.group.clear();
                    }
                    if st.cfg.selected_profile().is_none() {
                        st.cfg.selected = st.cfg.profiles.first().map(|p| p.id.clone()).unwrap_or_default();
                    }
                    st.save();
                    ui.set_subs(model(st.sub_items()));
                }
                "apply-preset" => {
                    let i = arg.parse::<usize>().unwrap_or(0).min(PRESETS.len() - 1);
                    apply_preset(&mut st.cfg.routing, PRESETS[i].0);
                    st.save();
                    refresh_routing(&ui, &st);
                    drop(st);
                    toast(&ui, "Набор правил применён");
                    restart_if_running(&h);
                }
                "delete-rule" => {
                    st.cfg.routing.rules.retain(|r| r.id != arg);
                    st.save();
                    refresh_routing(&ui, &st);
                    ui.set_page("routing".into());
                }
                "delete-split" => {
                    st.cfg.splits.retain(|x| x.id != arg);
                    st.save();
                    refresh_routing(&ui, &st);
                    ui.set_page("routing".into());
                    drop(st);
                    restart_if_running(&h);
                }
                _ => {}
            }
        });
    }
    {
        let s = st.clone();
        let h = host.clone();
        let w = ui.as_weak();
        ui.on_form_save(move || {
            let ui = w.unwrap();
            let f = ui.get_form();
            let res = {
                let st = s.borrow();
                let base = st.cfg.profiles.iter().find(|p| p.id == f.id.as_str());
                state::form_to_profile(&f, base)
            };
            match res {
                Ok(p) => {
                    let is_selected;
                    {
                        let mut st = s.borrow_mut();
                        is_selected = st.cfg.selected == p.id;
                        if let Some(x) = st.cfg.profiles.iter_mut().find(|x| x.id == p.id) {
                            *x = p;
                        } else {
                            let mut p = p;
                            if let Some(g) = st.local_group() {
                                p.sub_id = g;
                            }
                            let id = p.id.clone();
                            st.cfg.profiles.push(p);
                            if st.cfg.selected_profile().is_none() {
                                st.cfg.selected = id;
                            }
                        }
                        st.save();
                        refresh_servers(&ui, &st);
                    }
                    ui.set_page("main".into());
                    ui.invoke_focus_keys();
                    toast(&ui, "Сохранено");
                    if is_selected {
                        restart_if_running(&h);
                    }
                }
                Err(e) => toast(&ui, &e),
            }
        });
    }
    {
        let w = ui.as_weak();
        ui.on_form_protocol_changed(move |p| {
            let ui = w.unwrap();
            let mut f = ui.get_form();
            f.method_index = 0;
            if p == 2 && f.security == 0 {
                f.security = 1;
            }
            if p > 2 {
                f.security = 0;
                f.network = 0;
            }
            if p != 0 {
                f.flow = 0;
                if f.security == 2 {
                    f.security = 1;
                }
            }
            ui.set_form(f);
        });
    }

    // ── подписки ──
    {
        let s = st.clone();
        let h = host.clone();
        let w = ui.as_weak();
        ui.on_sub_save(move || {
            let ui = w.unwrap();
            let (id, name, url) = (ui.get_sub_id().to_string(), ui.get_sub_name().to_string(), ui.get_sub_url().trim().to_string());
            // пустой URL — группа без ссылки: вкладка создаётся без импорта подписки
            let url = if ui.get_sub_group() { String::new() } else { url };
            if !url.is_empty() && !url.starts_with("http://") && !url.starts_with("https://") {
                toast(&ui, "URL подписки должен начинаться с http(s)://");
                return;
            }
            let new_id = {
                let mut st = s.borrow_mut();
                let new_id = if id.is_empty() {
                    let nid = Profile::new_id();
                    let n = st.cfg.subscriptions.len() + 1;
                    let local = url.is_empty();
                    let default_name = if local { format!("Группа {n}") } else { format!("Подписка {n}") };
                    st.cfg.subscriptions.push(Subscription {
                        id: nid.clone(),
                        remarks: if name.trim().is_empty() { default_name } else { name.trim().into() },
                        custom_name: local || !name.trim().is_empty(),
                        url,
                        enabled: true,
                        ..Default::default()
                    });
                    if local {
                        // сразу открыть новую вкладку на главном экране
                        st.group = nid.clone();
                        refresh_servers(&ui, &st);
                    }
                    Some((nid, local))
                } else {
                    if let Some(x) = st.cfg.subscriptions.iter_mut().find(|x| x.id == id) {
                        if x.remarks != name.trim() {
                            x.custom_name = true;
                        }
                        x.remarks = name.trim().into();
                        x.url = url;
                    }
                    refresh_servers(&ui, &st);
                    None
                };
                st.save();
                ui.set_subs(model(st.sub_items()));
                new_id
            };
            match new_id {
                Some((_, true)) => toast(&ui, "Группа создана — добавляйте в неё серверы через «+» на главном экране"),
                Some((nid, false)) => update_subs(&ui, &s, &h, Some(nid)),
                None => {}
            }
        });
    }
    {
        let s = st.clone();
        let w = ui.as_weak();
        ui.on_sub_edit(move |id| {
            let ui = w.unwrap();
            if let Some(x) = s.borrow().cfg.subscriptions.iter().find(|x| x.id == id.as_str()) {
                ui.set_sub_id(x.id.clone().into());
                ui.set_sub_name(x.remarks.clone().into());
                ui.set_sub_url(x.url.clone().into());
                ui.set_sub_group(x.url.trim().is_empty());
                ui.set_sub_dialog(true);
            }
        });
    }
    {
        let w = ui.as_weak();
        ui.on_sub_new(move || {
            let ui = w.unwrap();
            ui.set_sub_id(SharedString::new());
            ui.set_sub_name(SharedString::new());
            ui.set_sub_url(SharedString::new());
            ui.set_sub_group(false);
            ui.set_sub_dialog(true);
        });
    }
    {
        let w = ui.as_weak();
        ui.on_group_new(move || {
            let ui = w.unwrap();
            ui.set_sub_id(SharedString::new());
            ui.set_sub_name(SharedString::new());
            ui.set_sub_url(SharedString::new());
            ui.set_sub_group(true);
            ui.set_sub_dialog(true);
        });
    }
    {
        let s = st.clone();
        let h = host.clone();
        let w = ui.as_weak();
        ui.on_sub_refresh(move |id| update_subs(&w.unwrap(), &s, &h, Some(id.to_string())));
    }
    {
        let s = st.clone();
        ui.on_sub_auto_changed(move |v| {
            let mut st = s.borrow_mut();
            st.cfg.settings.sub_auto_update = v;
            st.save();
        });
    }
    {
        let s = st.clone();
        let h = host.clone();
        let w = ui.as_weak();
        ui.on_subs_update(move || update_subs(&w.unwrap(), &s, &h, None));
    }

    // ── маршрутизация ──
    {
        let s = st.clone();
        let w = ui.as_weak();
        ui.on_routing_changed(move || {
            let ui = w.unwrap();
            let mut st = s.borrow_mut();
            st.cfg.routing.domain_strategy = ["AsIs", "IPIfNonMatch", "IPOnDemand"][ui.get_strategy_index().clamp(0, 2) as usize].into();
            st.cfg.routing.final_outbound = OutboundTag::from_index(ui.get_final_index());
            st.save();
        });
    }
    {
        let s = st.clone();
        let w = ui.as_weak();
        ui.on_rule_open(move |id| {
            let ui = w.unwrap();
            let st = s.borrow();
            match st.cfg.routing.rules.iter().find(|r| r.id == id.as_str()) {
                Some(r) => {
                    ui.set_rule_form(state::rule_to_form(r));
                    ui.set_rule_is_new(false);
                }
                None => {
                    ui.set_rule_form(state::rule_to_form(&xd_core::config::RoutingRule {
                        enabled: true,
                        outbound: OutboundTag::Direct,
                        ..Default::default()
                    }));
                    ui.set_rule_is_new(true);
                }
            }
            ui.set_page("rule".into());
            ui.invoke_focus_keys();
        });
    }
    {
        let s = st.clone();
        ui.on_rule_toggle(move |id, v| {
            let mut st = s.borrow_mut();
            if let Some(r) = st.cfg.routing.rules.iter_mut().find(|r| r.id == id.as_str()) {
                r.enabled = v;
            }
            st.save();
        });
    }
    {
        let s = st.clone();
        let w = ui.as_weak();
        ui.on_rule_move(move |id, d| {
            let ui = w.unwrap();
            let mut st = s.borrow_mut();
            if let Some(i) = st.cfg.routing.rules.iter().position(|r| r.id == id.as_str()) {
                let j = i as i32 + d;
                if j >= 0 && (j as usize) < st.cfg.routing.rules.len() {
                    st.cfg.routing.rules.swap(i, j as usize);
                }
            }
            st.save();
            ui.set_rules(model(st.rule_items()));
        });
    }
    {
        let s = st.clone();
        let w = ui.as_weak();
        ui.on_rule_save(move || {
            let ui = w.unwrap();
            let r = state::form_to_rule(&ui.get_rule_form());
            if r.domain.is_empty() && r.ip.is_empty() && r.port.is_empty() && r.network.is_empty() && r.protocol.is_empty() {
                toast(&ui, "Укажите хотя бы одно условие (домены, IP, порт…)");
                return;
            }
            let mut st = s.borrow_mut();
            if let Some(x) = st.cfg.routing.rules.iter_mut().find(|x| x.id == r.id) {
                *x = r;
            } else {
                st.cfg.routing.rules.push(r);
            }
            st.save();
            refresh_routing(&ui, &st);
            ui.set_page("routing".into());
            ui.invoke_focus_keys();
        });
    }
    {
        let s = st.clone();
        let w = ui.as_weak();
        ui.on_geo_download(move || {
            let ui = w.unwrap();
            let (dir, ip_url, site_url) = {
                let st = s.borrow();
                (st.dir.clone(), st.cfg.routing.geoip_url.clone(), st.cfg.routing.geosite_url.clone())
            };
            ui.set_geo_busy(true);
            let w = ui.as_weak();
            std::thread::spawn(move || {
                let mut errs = Vec::new();
                for (url, name) in [(ip_url, "geoip.dat"), (site_url, "geosite.dat")] {
                    let w2 = w.clone();
                    let r = xd_core::subscription::download(&url, &dir.join(name), &move |n| {
                        let t = format!("Загрузка {name}: {}", fmt_bytes(n as f64));
                        let _ = w2.upgrade_in_event_loop(move |ui| ui.set_geo_status(t.into()));
                    });
                    if let Err(e) = r {
                        log::warn!("{name}: {e}");
                        errs.push(format!("{name}: {e}"));
                    }
                }
                let _ = w.upgrade_in_event_loop(move |ui| {
                    ui.set_geo_busy(false);
                    with_state(|st| ui.set_geo_status(st.borrow().geo_status().into()));
                    if errs.is_empty() {
                        toast(&ui, "Geo-файлы обновлены");
                    } else {
                        toast(&ui, &format!("Ошибка загрузки: {}", errs.join("; ")));
                    }
                });
            });
        });
    }

    // ── маршруты на отдельные серверы ──
    {
        let s = st.clone();
        let h = host.clone();
        let w = ui.as_weak();
        ui.on_split_open(move |id| {
            let ui = w.unwrap();
            {
                let mut st = s.borrow_mut();
                match st.cfg.splits.iter().find(|x| x.id == id.as_str()).cloned() {
                    Some(sp) => {
                        ui.set_split_form(state::split_to_form(&sp));
                        ui.set_split_is_new(false);
                        st.split_apps = sp.apps.iter().cloned().collect();
                        st.split_server = sp.server.clone();
                    }
                    None => {
                        ui.set_split_form(SplitForm::default());
                        ui.set_split_is_new(true);
                        st.split_apps.clear();
                        st.split_server.clear();
                    }
                }
                st.split_filter.clear();
                ui.set_split_filter(SharedString::new());
                refresh_split_servers(&ui, &st);
                refresh_split_apps(&ui, &st);
            }
            load_apps(&ui, &s, &h);
            ui.set_page("split".into());
            ui.invoke_focus_keys();
        });
    }
    {
        let s = st.clone();
        let w = ui.as_weak();
        ui.on_split_pick_server(move |id| {
            let ui = w.unwrap();
            let mut st = s.borrow_mut();
            st.split_server = id.to_string();
            refresh_split_servers(&ui, &st);
        });
    }
    {
        let s = st.clone();
        let w = ui.as_weak();
        ui.on_split_app_toggle(move |pkg, v| {
            let ui = w.unwrap();
            let mut st = s.borrow_mut();
            if v {
                st.split_apps.insert(pkg.to_string());
            } else {
                st.split_apps.remove(pkg.as_str());
            }
            refresh_split_apps(&ui, &st);
        });
    }
    {
        let s = st.clone();
        let w = ui.as_weak();
        ui.on_split_filter_changed(move |f| {
            let ui = w.unwrap();
            let mut st = s.borrow_mut();
            st.split_filter = f.to_string();
            refresh_split_apps(&ui, &st);
        });
    }
    {
        let s = st.clone();
        let h = host.clone();
        let w = ui.as_weak();
        ui.on_split_save(move || {
            let ui = w.unwrap();
            let f = ui.get_split_form();
            let res = {
                let st = s.borrow();
                let enabled = st.cfg.splits.iter().find(|x| x.id == f.id.as_str()).map(|x| x.enabled).unwrap_or(true);
                state::form_to_split(&f, &st.split_server, &st.split_apps, enabled)
            };
            match res {
                Ok(sp) => {
                    {
                        let mut st = s.borrow_mut();
                        match st.cfg.splits.iter_mut().find(|x| x.id == sp.id) {
                            Some(x) => *x = sp,
                            None => st.cfg.splits.push(sp),
                        }
                        st.save();
                        refresh_routing(&ui, &st);
                    }
                    ui.set_page("routing".into());
                    ui.invoke_focus_keys();
                    toast(&ui, "Маршрут сохранён");
                    restart_if_running(&h);
                }
                Err(e) => toast(&ui, &e),
            }
        });
    }
    {
        let s = st.clone();
        let h = host.clone();
        ui.on_split_toggle(move |id, v| {
            let mut st = s.borrow_mut();
            if let Some(x) = st.cfg.splits.iter_mut().find(|x| x.id == id.as_str()) {
                x.enabled = v;
            }
            st.save();
            drop(st);
            restart_if_running(&h);
        });
    }

    // ── настройки ──
    {
        let s = st.clone();
        let w = ui.as_weak();
        ui.on_settings_save(move || {
            let ui = w.unwrap();
            let mut st = s.borrow_mut();
            let f = ui.get_settings();
            state::form_to_settings(&f, &mut st.cfg.settings);
            st.save();
            ui.set_apps_summary(st.apps_summary().into());
        });
    }

    // ── приложения ──
    {
        let s = st.clone();
        let h = host.clone();
        let w = ui.as_weak();
        ui.on_apps_mode_changed(move |m| {
            let ui = w.unwrap();
            {
                let mut st = s.borrow_mut();
                st.cfg.settings.per_app_mode = m;
                st.save();
            }
            if m != 0 {
                load_apps(&ui, &s, &h);
            }
            refresh_apps(&ui, &s.borrow());
        });
    }
    {
        let s = st.clone();
        let w = ui.as_weak();
        ui.on_apps_filter_changed(move |f| {
            let ui = w.unwrap();
            let mut st = s.borrow_mut();
            st.apps_filter = f.to_string();
            refresh_apps(&ui, &st);
        });
    }
    {
        let s = st.clone();
        let w = ui.as_weak();
        ui.on_app_toggle(move |pkg, v| {
            let ui = w.unwrap();
            let mut st = s.borrow_mut();
            let list = &mut st.cfg.settings.per_app_list;
            list.retain(|p| p != pkg.as_str());
            if v {
                list.push(pkg.to_string());
            }
            st.save();
            refresh_apps(&ui, &st);
        });
    }
    {
        let s = st.clone();
        let w = ui.as_weak();
        ui.on_apps_select_all(move |v| {
            let ui = w.unwrap();
            let mut st = s.borrow_mut();
            let visible: Vec<String> = st.app_items().0.iter().map(|a| a.pkg.to_string()).collect();
            let list = &mut st.cfg.settings.per_app_list;
            list.retain(|p| !visible.contains(p));
            if v {
                list.extend(visible);
            }
            st.save();
            refresh_apps(&ui, &st);
        });
    }

    // ── журнал ──
    {
        let w = ui.as_weak();
        ui.on_logs_refresh(move || w.unwrap().set_logs(state::strings(xd_core::logbuf::tail_file(400))));
    }
    {
        let w = ui.as_weak();
        ui.on_logs_clear(move || {
            xd_core::logbuf::clear();
            w.unwrap().set_logs(state::strings(vec![]));
        });
    }
    {
        let h = host.clone();
        let w = ui.as_weak();
        ui.on_logs_copy(move || {
            h.set_clipboard(&xd_core::logbuf::tail_file(400).join("\n"));
            toast(&w.unwrap(), "Журнал скопирован");
        });
    }
    // ── обновление приложения ──
    {
        let h = host.clone();
        ui.on_update_check(move || h.check_update());
        let h = host.clone();
        ui.on_update_start(move || h.start_update());
    }

    // ── автообновление подписок старше суток ──
    {
        let stale = st
            .borrow()
            .cfg
            .subscriptions
            .iter()
            .any(|x| x.enabled && !x.url.trim().is_empty() && state::now_secs() - x.last_update > 24 * 3600);
        if stale && st.borrow().cfg.settings.sub_auto_update {
            let s = st.clone();
            let h = host.clone();
            let w = ui.as_weak();
            Timer::single_shot(Duration::from_secs(2), move || {
                if let Some(ui) = w.upgrade() {
                    update_subs(&ui, &s, &h, None);
                }
            });
        }
    }

    Ok(ui)
}

/// Обновление статуса VPN в интерфейсе.
pub fn apply_status(ui: &MainWindow, last: &RefCell<Option<(u64, u64, std::time::Instant)>>) {
    let s = status::get();
    ui.set_running(s.running);
    ui.set_connecting(s.connecting);
    ui.set_status_error(false);
    if s.connecting {
        ui.set_status_title(if s.running { "Отключение…" } else { "Подключение…" }.into());
        ui.set_status_sub("Подождите".into());
        return;
    }
    // таймер идёт только при работающем VPN, иначе — нули
    let secs = if s.running && s.error.is_empty() && s.started_ms > 0 { (state::now_secs() * 1000 - s.started_ms) / 1000 } else { 0 };
    ui.set_timer_text(fmt_uptime(secs).into());
    if !s.error.is_empty() {
        ui.set_status_error(true);
        ui.set_status_title("Ошибка".into());
        ui.set_status_sub(s.error.clone().into());
    } else {
        ui.set_status_title(if s.running { "Защищено" } else { "Не подключено" }.into());
        ui.set_status_sub(SharedString::new());
    }
    if s.running {
        let now = std::time::Instant::now();
        let mut l = last.borrow_mut();
        if let Some((u, d, t)) = *l {
            if s.up >= u && s.down >= d {
                let dt = now.duration_since(t).as_secs_f64().max(0.2);
                let (dv, du) = speed_parts((s.down - d) as f64 / dt);
                let (uv, uu) = speed_parts((s.up - u) as f64 / dt);
                ui.set_down_value(dv.into());
                ui.set_down_unit(du.into());
                ui.set_up_value(uv.into());
                ui.set_up_unit(uu.into());
            }
        }
        *l = Some((s.up, s.down, now));
    } else {
        *last.borrow_mut() = None;
        ui.set_down_value("0".into());
        ui.set_down_unit("КБ/с".into());
        ui.set_up_value("0".into());
        ui.set_up_unit("КБ/с".into());
    }
}

/// Состояние обновления приложения от платформы (числа состояний — как в Updater.java).
/// `prompt` — найдена новая версия, нужно спросить пользователя.
pub fn apply_update(ui: &MainWindow, state: i32, version: &str, current: &str, progress: i32, message: &str, prompt: bool) {
    ui.set_update_state(state);
    ui.set_update_version(version.into());
    ui.set_update_current(current.into());
    ui.set_update_progress(progress.clamp(0, 100));
    ui.set_update_message(message.into());
    if prompt {
        ui.set_update_dialog(true);
    } else if state != 2 {
        ui.set_update_dialog(false);
    }
}

#[allow(dead_code)]
pub fn weak_noop(_: Weak<MainWindow>) {}
