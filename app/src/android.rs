//! Android: точка входа NativeActivity, вызовы Java-слоя и JNI-функции для VpnService.

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use jni::objects::{GlobalRef, JClass, JObject, JString, JValue};
use jni::sys::{jboolean, jint, jlong, jstring};
use jni::{JNIEnv, JavaVM};
use parking_lot::Mutex;
use slint::ComponentHandle;
use xd_core::config::AppConfig;

use crate::{status, Host};

fn logcat(line: &str) {
    extern "C" {
        fn __android_log_write(prio: i32, tag: *const std::ffi::c_char, text: *const std::ffi::c_char) -> i32;
    }
    if let Ok(t) = std::ffi::CString::new(line.replace('\0', " ")) {
        unsafe { __android_log_write(4, c"XrayDroid".as_ptr(), t.as_ptr()) };
    }
}

fn init_logging(dir: &std::path::Path) {
    xd_core::logbuf::init(Some(dir.join("log.txt")), false);
    xd_core::logbuf::set_sink(logcat);
    std::panic::set_hook(Box::new(|info| {
        logcat(&format!("PANIC: {info}"));
        log::error!("PANIC: {info}");
    }));
}

struct AndroidHost {
    vm: JavaVM,
    activity: GlobalRef,
}

impl AndroidHost {
    fn call<F, R>(&self, f: F) -> Option<R>
    where
        F: FnOnce(&mut JNIEnv, &JObject) -> jni::errors::Result<R>,
    {
        let mut env = self.vm.attach_current_thread().ok()?;
        match f(&mut env, self.activity.as_obj()) {
            Ok(r) => Some(r),
            Err(e) => {
                let _ = env.exception_describe();
                let _ = env.exception_clear();
                log::error!("JNI: {e}");
                None
            }
        }
    }

    fn call_void(&self, name: &str) {
        self.call(|env, act| env.call_method(act, name, "()V", &[]).map(|_| ()));
    }
}

impl Host for AndroidHost {
    fn start_vpn(&self) {
        self.call_void("startVpn");
    }
    fn stop_vpn(&self) {
        self.call_void("stopVpn");
    }
    fn get_clipboard(&self) -> Option<String> {
        self.call(|env, act| {
            let o = env.call_method(act, "getClipboardText", "()Ljava/lang/String;", &[])?.l()?;
            if o.is_null() {
                return Ok(None);
            }
            let s: String = env.get_string(&JString::from(o))?.into();
            Ok(Some(s))
        })
        .flatten()
        .filter(|s| !s.trim().is_empty())
    }
    fn set_clipboard(&self, text: &str) {
        self.call(|env, act| {
            let s = env.new_string(text)?;
            env.call_method(act, "setClipboardText", "(Ljava/lang/String;)V", &[JValue::Object(&s)]).map(|_| ())
        });
    }
    fn check_update(&self) {
        self.call_void("checkUpdate");
    }
    fn start_update(&self) {
        self.call_void("startUpdate");
    }
    fn installed_apps(&self) -> Vec<(String, String)> {
        let json = self
            .call(|env, act| {
                let o = env.call_method(act, "getInstalledAppsJson", "()Ljava/lang/String;", &[])?.l()?;
                let s: String = env.get_string(&JString::from(o))?.into();
                Ok(s)
            })
            .unwrap_or_default();
        serde_json::from_str::<Vec<(String, String)>>(&json).unwrap_or_default()
    }
}

static UI: OnceLock<Mutex<Option<slint::Weak<crate::MainWindow>>>> = OnceLock::new();

/// Вызовы Java из ядра (процесс VPN): владелец соединения и UID приложения.
struct JavaHooks {
    vm: JavaVM,
    class: GlobalRef,
}

impl JavaHooks {
    fn call_int(&self, name: &str, sig: &str, args: &[JValue]) -> Option<i32> {
        let mut env = self.vm.attach_current_thread().ok()?;
        let cls = JClass::from(env.new_local_ref(self.class.as_obj()).ok()?);
        match env.call_static_method(&cls, name, sig, args) {
            Ok(v) => v.i().ok(),
            Err(_) => {
                let _ = env.exception_clear();
                None
            }
        }
    }
}

impl xd_core::tun::PlatformHooks for JavaHooks {
    fn owner_uid(&self, tcp: bool, src: std::net::SocketAddr, dst: std::net::SocketAddr) -> Option<u32> {
        let mut env = self.vm.attach_current_thread().ok()?;
        let s = env.new_string(src.ip().to_string()).ok()?;
        let d = env.new_string(dst.ip().to_string()).ok()?;
        let args = [
            JValue::Int(if tcp { 6 } else { 17 }),
            JValue::Object(&s),
            JValue::Int(src.port() as i32),
            JValue::Object(&d),
            JValue::Int(dst.port() as i32),
        ];
        let cls = JClass::from(env.new_local_ref(self.class.as_obj()).ok()?);
        let r = match env.call_static_method(&cls, "ownerUid", "(ILjava/lang/String;ILjava/lang/String;I)I", &args) {
            Ok(v) => v.i().ok(),
            Err(_) => {
                let _ = env.exception_clear();
                None
            }
        }?;
        (r >= 0).then_some(r as u32)
    }

    fn package_uid(&self, package: &str) -> Option<u32> {
        let mut env = self.vm.attach_current_thread().ok()?;
        let p = env.new_string(package).ok()?;
        let cls = JClass::from(env.new_local_ref(self.class.as_obj()).ok()?);
        let r = match env.call_static_method(&cls, "packageUid", "(Ljava/lang/String;)I", &[JValue::Object(&p)]) {
            Ok(v) => v.i().ok(),
            Err(_) => {
                let _ = env.exception_clear();
                None
            }
        }?;
        (r >= 0).then_some(r as u32)
    }
}

static HOOKS_ONCE: std::sync::Once = std::sync::Once::new();

#[no_mangle]
fn android_main(app: slint::android::AndroidApp) {
    let dir: PathBuf = app.internal_data_path().unwrap_or_else(|| PathBuf::from("/data/local/tmp"));
    init_logging(&dir);
    let vm = unsafe { JavaVM::from_raw(app.vm_as_ptr() as *mut jni::sys::JavaVM) }.expect("vm");
    let activity = {
        let env = vm.attach_current_thread().expect("attach");
        let obj = unsafe { JObject::from_raw(app.activity_as_ptr() as jni::sys::jobject) };
        env.new_global_ref(obj).expect("global ref")
    };
    let host = Arc::new(AndroidHost { vm, activity });
    slint::android::init(app).expect("slint init");
    crate::fonts::setup_emoji_flags();
    let ui = crate::ui::build(dir, host.clone()).expect("ui");
    *UI.get_or_init(|| Mutex::new(None)).lock() = Some(ui.as_weak());
    host.call_void("onUiReady");
    ui.run().expect("run");
}

fn jstr(env: &mut JNIEnv, s: &JString) -> String {
    env.get_string(s).map(|s| s.into()).unwrap_or_default()
}

fn new_jstring(env: &mut JNIEnv, s: &str) -> jstring {
    env.new_string(s).map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut())
}

// ───────────────── процесс UI: статус от сервиса ─────────────────

#[no_mangle]
pub extern "system" fn Java_com_xraydroid_XrayCore_nativeOnStatus(
    mut env: JNIEnv,
    _: JClass,
    running: jboolean,
    error: JString,
    up: jlong,
    down: jlong,
    started_ms: jlong,
) {
    let err = jstr(&mut env, &error);
    status::on_service(running != 0, &err, up as u64, down as u64, started_ms);
    if let Some(w) = UI.get().and_then(|m| m.lock().clone()) {
        let _ = w.upgrade_in_event_loop(|ui| {
            crate::ui::apply_status(&ui, &std::cell::RefCell::new(None));
        });
    }
}

/// Состояние обновления приложения от Updater.java.
#[no_mangle]
pub extern "system" fn Java_com_xraydroid_XrayCore_nativeOnUpdate(
    mut env: JNIEnv,
    _: JClass,
    state: jint,
    version: JString,
    current: JString,
    progress: jint,
    message: JString,
    prompt: jboolean,
) {
    let version = jstr(&mut env, &version);
    let current = jstr(&mut env, &current);
    let message = jstr(&mut env, &message);
    let prompt = prompt != 0;
    if let Some(w) = UI.get().and_then(|m| m.lock().clone()) {
        let _ = w.upgrade_in_event_loop(move |ui| {
            crate::ui::apply_update(&ui, state, &version, &current, progress, &message, prompt);
        });
    }
}

// ───────────────── процесс VPN-сервиса ─────────────────

struct ServiceState {
    cfg: AppConfig,
    dir: PathBuf,
}

static SERVICE: Mutex<Option<ServiceState>> = Mutex::new(None);

/// Читает настройки и возвращает JSON с параметрами для VpnService.Builder.
#[no_mangle]
pub extern "system" fn Java_com_xraydroid_XrayCore_nativePrepare(mut env: JNIEnv, class: JClass, files_dir: JString) -> jstring {
    let dir = PathBuf::from(jstr(&mut env, &files_dir));
    init_logging(&dir);
    HOOKS_ONCE.call_once(|| {
        if let (Ok(vm), Ok(class)) = (env.get_java_vm(), env.new_global_ref(&class)) {
            xd_core::engine::set_platform_hooks(Arc::new(JavaHooks { vm, class }));
        }
    });
    let cfg = AppConfig::load(&dir.join("config.json"));
    let p = cfg.selected_profile().cloned();
    let s = &cfg.settings;
    let json = serde_json::json!({
        "error": if p.is_none() { "не выбран сервер" } else { "" },
        "name": p.map(|p| p.display_name()).unwrap_or_default(),
        "mtu": s.mtu,
        "ipv6": s.ipv6,
        "mode": s.per_app_mode,
        "apps": s.per_app_list,
    })
    .to_string();
    *SERVICE.lock() = Some(ServiceState { cfg, dir });
    new_jstring(&mut env, &json)
}

/// Запуск ядра на дескрипторе TUN. Возвращает пустую строку или текст ошибки.
#[no_mangle]
pub extern "system" fn Java_com_xraydroid_XrayCore_nativeStart(mut env: JNIEnv, _: JClass, fd: jint) -> jstring {
    let r = match SERVICE.lock().as_ref() {
        Some(s) => xd_core::engine::start(&s.cfg, &s.dir, Some(fd)).map_err(|e| e.to_string()),
        None => Err("nativePrepare не вызван".into()),
    };
    let msg = match r {
        Ok(()) => String::new(),
        Err(e) => {
            log::error!("запуск: {e}");
            e
        }
    };
    new_jstring(&mut env, &msg)
}

#[no_mangle]
pub extern "system" fn Java_com_xraydroid_XrayCore_nativeStop(_env: JNIEnv, _: JClass) {
    xd_core::engine::stop();
}

/// [отправлено, получено]
#[no_mangle]
pub extern "system" fn Java_com_xraydroid_XrayCore_nativeStats<'a>(env: JNIEnv<'a>, _: JClass<'a>) -> jni::sys::jlongArray {
    let (up, down) = xd_core::engine::stats().map(|s| (s.0 as i64, s.1 as i64)).unwrap_or((0, 0));
    match env.new_long_array(2) {
        Ok(arr) => {
            let _ = env.set_long_array_region(&arr, 0, &[up, down]);
            arr.into_raw()
        }
        Err(_) => std::ptr::null_mut(),
    }
}
