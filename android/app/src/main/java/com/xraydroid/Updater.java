package com.xraydroid;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageInstaller;
import android.os.Build;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 * Автообновление из релизов GitHub: проверка версии, загрузка APK прямо в сессию
 * PackageInstaller и установка поверх. На Android 12+ обновление самого себя ставится
 * без системного диалога; на более старых система спрашивает подтверждение.
 * Подпись APK должна совпадать с установленным (один и тот же ключ).
 *
 * Состояние показывает интерфейс (Rust/Slint) — сюда оно уходит через nativeOnUpdate.
 * После замены пакета приложение поднимает {@link UpdateReceiver}.
 */
final class Updater {
    private static final String REPO = "frd21313123123/XrayDroid";
    static final String ACTION_RESULT = "com.xraydroid.UPDATE_RESULT";

    static final String PREFS = "update";
    static final String KEY_PENDING_AT = "pending_at";
    static final String KEY_VPN = "vpn";
    static final String KEY_VERSION = "version";

    // Состояния — те же числа, что в app/src/update.rs.
    static final int IDLE = 0, CHECKING = 1, AVAILABLE = 2, DOWNLOADING = 3, INSTALLING = 4, ERROR = 5, LATEST = 6;

    private static final long RECHECK_MS = 6 * 3600_000L;

    /** Текущий экземпляр — ему UpdateReceiver передаёт результат установки. */
    static volatile Updater instance;

    private final MainActivity activity;
    private Release release;
    private volatile int state = IDLE;
    private int progress;
    private String message = "";
    private boolean uiReady;
    private boolean promptPending;
    private String promptedVersion = "";
    private long lastCheck;
    private int sessionId = -1;

    Updater(MainActivity activity) {
        this.activity = activity;
        instance = this;
    }

    void release() {
        if (instance == this) instance = null;
    }

    /** Интерфейс готов принимать состояние. */
    void onUiReady() {
        uiReady = true;
        emit();
    }

    /** Автопроверка: при запуске и при возврате в приложение, не чаще раза в 6 часов. */
    void checkAuto() {
        if (lastCheck != 0 && System.currentTimeMillis() - lastCheck < RECHECK_MS) return;
        check(false);
    }

    /** Проверка версии. manual — по кнопке в настройках (тогда показываются и ошибки). */
    void check(boolean manual) {
        if (state == CHECKING || state == DOWNLOADING || state == INSTALLING) return;
        lastCheck = System.currentTimeMillis();
        if (manual) set(CHECKING, 0, "");
        new Thread(() -> {
            Release r = null;
            String error = null;
            try {
                r = fetchLatest();
            } catch (Exception e) {
                error = "Не удалось проверить обновления: " + text(e);
            }
            final Release found = r;
            final String err = error;
            activity.runOnUiThread(() -> onChecked(found, err, manual));
        }, "xd-update-check").start();
    }

    private void onChecked(Release r, String error, boolean manual) {
        if (state == DOWNLOADING || state == INSTALLING) return;
        if (r != null && isNewer(r.version, currentVersion())) {
            release = r;
            // Сам спрашивает только при автопроверке и один раз на версию за запуск.
            if (!manual && !r.version.equals(promptedVersion)) {
                promptedVersion = r.version;
                promptPending = true;
            }
            set(AVAILABLE, 0, "");
        } else if (manual) {
            if (error != null) set(ERROR, 0, error);
            else set(LATEST, 0, "");
        }
    }

    /** Пользователь согласился: загрузка и установка. */
    void start() {
        if (release == null || state == DOWNLOADING || state == INSTALLING) return;
        final Release r = release;
        final boolean vpn = activity.isVpnRunning();
        set(DOWNLOADING, 0, "");
        new Thread(() -> {
            try {
                downloadAndInstall(r, vpn);
            } catch (Exception e) {
                abandon();
                clearPending(activity);
                activity.runOnUiThread(() -> set(ERROR, 0, "Не удалось скачать обновление: " + text(e)));
            }
        }, "xd-update-download").start();
    }

    // ───── состояние ─────

    private void set(int state, int progress, String message) {
        this.state = state;
        this.progress = progress;
        this.message = message == null ? "" : message;
        emit();
    }

    private void emit() {
        if (!uiReady) return;
        boolean prompt = promptPending && state == AVAILABLE;
        if (prompt) promptPending = false;
        String v = release != null ? strip(release.version) : "";
        try {
            XrayCore.nativeOnUpdate(state, v, strip(currentVersion()), progress, message, prompt);
        } catch (Throwable ignored) {
        }
    }

    private static String strip(String v) {
        return v == null ? "" : v.replaceFirst("^[vV]", "");
    }

    private static String text(Exception e) {
        String m = e.getMessage();
        return m == null || m.isEmpty() ? e.getClass().getSimpleName() : m;
    }

    // ───── GitHub ─────

    private static final class Release {
        String version;
        String apkUrl;
        long size;
    }

    private Release fetchLatest() throws Exception {
        Release r = fetchFromApi();
        return r != null ? r : fetchFromRedirect();
    }

    /** Основной путь: API релизов. null — API недоступен (например, исчерпан лимит запросов). */
    private Release fetchFromApi() throws Exception {
        HttpURLConnection c = open("https://api.github.com/repos/" + REPO + "/releases/latest");
        String body;
        try {
            c.setRequestProperty("Accept", "application/vnd.github+json");
            if (c.getResponseCode() != 200) return null;
            try (InputStream in = c.getInputStream()) {
                body = new String(in.readAllBytes(), "UTF-8");
            }
        } finally {
            c.disconnect();
        }
        JSONObject j = new JSONObject(body);
        JSONArray assets = j.optJSONArray("assets");
        if (assets == null) return null;
        for (int i = 0; i < assets.length(); i++) {
            JSONObject a = assets.getJSONObject(i);
            if (a.optString("name").endsWith(".apk")) {
                Release r = new Release();
                r.version = j.getString("tag_name");
                r.apkUrl = a.getString("browser_download_url");
                r.size = a.optLong("size", 0);
                return r;
            }
        }
        return null;
    }

    /**
     * Запасной путь без API: /releases/latest перенаправляет на /releases/tag/&lt;тег&gt;,
     * а имя APK в релизе задаёт CI — XrayDroid-&lt;версия&gt;.apk.
     */
    private Release fetchFromRedirect() throws Exception {
        HttpURLConnection c = open("https://github.com/" + REPO + "/releases/latest");
        String location;
        try {
            c.setInstanceFollowRedirects(false);
            c.setRequestMethod("HEAD");
            int code = c.getResponseCode();
            if (code < 300 || code >= 400) throw new Exception("HTTP " + code);
            location = c.getHeaderField("Location");
        } finally {
            c.disconnect();
        }
        int at = location == null ? -1 : location.indexOf("/releases/tag/");
        if (at < 0) throw new Exception("релиз не найден");
        String tag = location.substring(at + "/releases/tag/".length());
        int cut = tag.indexOf('?');
        if (cut >= 0) tag = tag.substring(0, cut);
        if (tag.isEmpty()) throw new Exception("релиз не найден");
        Release r = new Release();
        r.version = tag;
        r.apkUrl = "https://github.com/" + REPO + "/releases/download/" + tag + "/XrayDroid-" + strip(tag) + ".apk";
        return r;
    }

    private static HttpURLConnection open(String url) throws Exception {
        HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
        c.setConnectTimeout(10_000);
        c.setReadTimeout(20_000);
        c.setInstanceFollowRedirects(true);
        c.setRequestProperty("User-Agent", "XrayDroid-Updater");
        return c;
    }

    // ───── версии ─────

    private String currentVersion() {
        try {
            return activity.getPackageManager().getPackageInfo(activity.getPackageName(), 0).versionName;
        } catch (Exception e) {
            return "";
        }
    }

    /** Версия вида «0.2.0-build.42»: сравниваем числа базовой версии, затем номер сборки. */
    static boolean isNewer(String remote, String local) {
        long[] a = parse(remote), b = parse(local);
        for (int i = 0; i < a.length; i++) {
            if (a[i] != b[i]) return a[i] > b[i];
        }
        return false;
    }

    private static long[] parse(String v) {
        long[] out = new long[4]; // major, minor, patch, build
        if (v == null) return out;
        v = v.trim();
        if (v.startsWith("v") || v.startsWith("V")) v = v.substring(1);
        String build = null;
        int dash = v.indexOf("-build.");
        if (dash >= 0) {
            build = v.substring(dash + 7);
            v = v.substring(0, dash);
        }
        String[] parts = v.split("\\.");
        for (int i = 0; i < 3 && i < parts.length; i++) out[i] = num(parts[i]);
        if (build != null) out[3] = num(build);
        return out;
    }

    private static long num(String s) {
        StringBuilder d = new StringBuilder();
        for (char ch : s.toCharArray()) {
            if (ch < '0' || ch > '9') break;
            d.append(ch);
        }
        try { return d.length() == 0 ? 0 : Long.parseLong(d.toString()); } catch (Exception e) { return 0; }
    }

    // ───── загрузка и установка ─────

    private void downloadAndInstall(Release r, boolean vpnWasRunning) throws Exception {
        PackageInstaller pi = activity.getPackageManager().getPackageInstaller();
        PackageInstaller.SessionParams params =
                new PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL);
        params.setAppPackageName(activity.getPackageName());
        if (Build.VERSION.SDK_INT >= 31) {
            // Обновление самого себя без системного диалога подтверждения.
            params.setRequireUserAction(PackageInstaller.SessionParams.USER_ACTION_NOT_REQUIRED);
        }
        int id = pi.createSession(params);
        sessionId = id;
        try (PackageInstaller.Session s = pi.openSession(id)) {
            HttpURLConnection c = open(r.apkUrl);
            try {
                if (c.getResponseCode() != 200) throw new Exception("HTTP " + c.getResponseCode());
                long length = c.getContentLengthLong();
                long total = length > 0 ? length : r.size;
                long done = 0;
                try (InputStream in = c.getInputStream();
                     OutputStream out = s.openWrite("update.apk", 0, total > 0 ? total : -1)) {
                    byte[] buf = new byte[64 * 1024];
                    int n, last = 0;
                    while ((n = in.read(buf)) > 0) {
                        out.write(buf, 0, n);
                        done += n;
                        if (total > 0) {
                            int p = (int) Math.min(100, done * 100 / total);
                            if (p != last) {
                                last = p;
                                activity.runOnUiThread(() -> {
                                    if (state == DOWNLOADING) set(DOWNLOADING, p, "");
                                });
                            }
                        }
                    }
                    s.fsync(out);
                }
                if (total > 0 && done != total) throw new Exception("загрузка оборвалась");
            } finally {
                c.disconnect();
            }

            // Процесс будет убит при замене пакета: что делать после — запоминаем заранее.
            activity.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
                    .putLong(KEY_PENDING_AT, System.currentTimeMillis())
                    .putBoolean(KEY_VPN, vpnWasRunning)
                    .putString(KEY_VERSION, strip(r.version))
                    .commit();
            activity.runOnUiThread(() -> set(INSTALLING, 100, ""));

            // Явный получатель: изменяемый PendingIntent с неявным интентом запрещён с Android 14.
            Intent cb = new Intent(activity, UpdateReceiver.class).setAction(ACTION_RESULT);
            int flags = PendingIntent.FLAG_UPDATE_CURRENT
                    | (Build.VERSION.SDK_INT >= 31 ? PendingIntent.FLAG_MUTABLE : 0);
            s.commit(PendingIntent.getBroadcast(activity, id, cb, flags).getIntentSender());
        }
    }

    private void abandon() {
        int id = sessionId;
        sessionId = -1;
        if (id < 0) return;
        try {
            activity.getPackageManager().getPackageInstaller().abandonSession(id);
        } catch (Exception ignored) {
        }
    }

    static void clearPending(Context c) {
        c.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().remove(KEY_PENDING_AT).apply();
    }

    /** Результат установки от системы (через UpdateReceiver, главный поток). */
    void onInstallResult(Intent intent) {
        int status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE);
        if (status == PackageInstaller.STATUS_PENDING_USER_ACTION) {
            // Системе всё же нужно подтверждение (Android до 12 или первый запуск установки).
            Intent confirm = Build.VERSION.SDK_INT >= 33
                    ? intent.getParcelableExtra(Intent.EXTRA_INTENT, Intent.class)
                    : intent.<Intent>getParcelableExtra(Intent.EXTRA_INTENT);
            if (confirm != null) {
                try {
                    activity.startActivity(confirm);
                    return;
                } catch (Exception ignored) {
                }
            }
            fail("Не удалось открыть подтверждение установки");
        } else if (status == PackageInstaller.STATUS_FAILURE_ABORTED) {
            // Пользователь отказался в системном диалоге.
            sessionId = -1;
            clearPending(activity);
            set(AVAILABLE, 0, "");
        } else if (status != PackageInstaller.STATUS_SUCCESS) {
            String m = intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE);
            fail("Не удалось установить обновление" + (m == null || m.isEmpty() ? "" : ": " + m));
        }
        // При успехе система завершает процесс и присылает MY_PACKAGE_REPLACED уже новой версии.
    }

    private void fail(String text) {
        sessionId = -1;
        clearPending(activity);
        set(ERROR, 0, text);
    }
}
