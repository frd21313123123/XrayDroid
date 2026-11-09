package com.xraydroid;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageInstaller;
import android.net.Uri;
import android.os.Build;
import android.provider.Settings;
import android.widget.ProgressBar;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 * Автообновление: при запуске сверяет версию с последним релизом на GitHub,
 * предлагает обновиться, скачивает APK и ставит его поверх через PackageInstaller.
 * Подпись APK должна совпадать с установленным (используется один и тот же ключ).
 */
final class Updater {
    private static final String REPO = "frd21313123123/XrayDroid";
    private static final String ACTION_RESULT = "com.xraydroid.UPDATE_RESULT";

    private final Activity activity;
    private boolean checked;
    private boolean busy;
    private BroadcastReceiver resultReceiver;

    Updater(Activity activity) {
        this.activity = activity;
    }

    /** Проверка один раз за запуск, в фоне; ошибки сети тихо игнорируются. */
    void checkOnStart() {
        if (checked) return;
        checked = true;
        new Thread(() -> {
            try {
                Release r = fetchLatest();
                if (r != null && isNewer(r.version, currentVersion())) {
                    activity.runOnUiThread(() -> askUser(r));
                }
            } catch (Exception ignored) {
            }
        }, "xd-update-check").start();
    }

    void release() {
        if (resultReceiver != null) {
            try { activity.unregisterReceiver(resultReceiver); } catch (Exception ignored) {}
            resultReceiver = null;
        }
    }

    // ───── GitHub ─────

    private static final class Release {
        String version;
        String apkUrl;
        long size;
        String notes;
    }

    private Release fetchLatest() throws Exception {
        HttpURLConnection c = open("https://api.github.com/repos/" + REPO + "/releases/latest");
        c.setRequestProperty("Accept", "application/vnd.github+json");
        if (c.getResponseCode() != 200) return null;
        String body;
        try (InputStream in = c.getInputStream()) {
            body = new String(in.readAllBytes(), "UTF-8");
        } finally {
            c.disconnect();
        }
        JSONObject j = new JSONObject(body);
        if (j.optBoolean("draft") || j.optBoolean("prerelease")) return null;
        JSONArray assets = j.optJSONArray("assets");
        if (assets == null) return null;
        for (int i = 0; i < assets.length(); i++) {
            JSONObject a = assets.getJSONObject(i);
            if (a.optString("name").endsWith(".apk")) {
                Release r = new Release();
                r.version = j.getString("tag_name");
                r.apkUrl = a.getString("browser_download_url");
                r.size = a.optLong("size", 0);
                r.notes = j.optString("body", "");
                return r;
            }
        }
        return null;
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

    private String currentVersion() throws Exception {
        return activity.getPackageManager().getPackageInfo(activity.getPackageName(), 0).versionName;
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

    // ───── диалоги ─────

    private void askUser(Release r) {
        if (activity.isFinishing() || busy) return;
        String msg = "Доступна новая версия " + r.version.replaceFirst("^[vV]", "")
                + (r.size > 0 ? " (" + (r.size / 1024 / 1024) + " МБ)" : "")
                + ".\nОбновить приложение сейчас?";
        new AlertDialog.Builder(activity)
                .setTitle("Доступно обновление")
                .setMessage(msg)
                .setPositiveButton("Обновить", (d, w) -> startUpdate(r))
                .setNegativeButton("Позже", null)
                .show();
    }

    private void startUpdate(Release r) {
        // Без разрешения «Установка неизвестных приложений» система не даст поставить APK.
        if (Build.VERSION.SDK_INT >= 26 && !activity.getPackageManager().canRequestPackageInstalls()) {
            new AlertDialog.Builder(activity)
                    .setTitle("Нужно разрешение")
                    .setMessage("Разрешите XrayDroid устанавливать приложения, затем нажмите «Обновить» снова.")
                    .setPositiveButton("Открыть настройки", (d, w) -> activity.startActivity(
                            new Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                                    Uri.parse("package:" + activity.getPackageName()))))
                    .setNegativeButton("Отмена", null)
                    .show();
            return;
        }
        busy = true;
        ProgressBar bar = new ProgressBar(activity, null, android.R.attr.progressBarStyleHorizontal);
        bar.setMax(100);
        bar.setPadding(64, 32, 64, 8);
        AlertDialog dialog = new AlertDialog.Builder(activity)
                .setTitle("Загрузка обновления")
                .setView(bar)
                .setCancelable(false)
                .show();
        new Thread(() -> {
            try {
                File apk = download(r, bar);
                activity.runOnUiThread(() -> {
                    dialog.dismiss();
                    bar.setIndeterminate(true);
                });
                install(apk);
            } catch (Exception e) {
                activity.runOnUiThread(() -> {
                    dialog.dismiss();
                    busy = false;
                    toastError("Не удалось скачать обновление: " + e.getMessage());
                });
            }
        }, "xd-update-download").start();
    }

    private File download(Release r, ProgressBar bar) throws Exception {
        File dir = new File(activity.getCacheDir(), "update");
        if (!dir.exists()) dir.mkdirs();
        File[] old = dir.listFiles();
        if (old != null) for (File f : old) f.delete();
        File out = new File(dir, "update.apk");
        HttpURLConnection c = open(r.apkUrl);
        try {
            if (c.getResponseCode() != 200) throw new Exception("HTTP " + c.getResponseCode());
            long total = c.getContentLengthLong() > 0 ? c.getContentLengthLong() : r.size;
            try (InputStream in = c.getInputStream(); OutputStream os = new java.io.FileOutputStream(out)) {
                byte[] buf = new byte[64 * 1024];
                long done = 0;
                int n, last = -1;
                while ((n = in.read(buf)) > 0) {
                    os.write(buf, 0, n);
                    done += n;
                    if (total > 0) {
                        int p = (int) (done * 100 / total);
                        if (p != last) {
                            last = p;
                            activity.runOnUiThread(() -> bar.setProgress(p));
                        }
                    }
                }
            }
        } finally {
            c.disconnect();
        }
        return out;
    }

    // ───── установка ─────

    private void install(File apk) throws Exception {
        PackageInstaller pi = activity.getPackageManager().getPackageInstaller();
        PackageInstaller.SessionParams params =
                new PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL);
        params.setAppPackageName(activity.getPackageName());
        int id = pi.createSession(params);
        try (PackageInstaller.Session s = pi.openSession(id)) {
            try (InputStream in = new FileInputStream(apk);
                 OutputStream out = s.openWrite("update.apk", 0, apk.length())) {
                byte[] buf = new byte[64 * 1024];
                int n;
                while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
                s.fsync(out);
            }
            activity.runOnUiThread(this::registerResultReceiver);
            Intent cb = new Intent(ACTION_RESULT).setPackage(activity.getPackageName());
            // Должен быть изменяемым: система дописывает в интент статус установки.
            int flags = PendingIntent.FLAG_UPDATE_CURRENT | (Build.VERSION.SDK_INT >= 31 ? PendingIntent.FLAG_MUTABLE : 0);
            PendingIntent pending = PendingIntent.getBroadcast(activity, id, cb, flags);
            s.commit(pending.getIntentSender());
        }
    }

    private void registerResultReceiver() {
        if (resultReceiver != null) return;
        resultReceiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                int status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE);
                if (status == PackageInstaller.STATUS_PENDING_USER_ACTION) {
                    // Системный экран подтверждения установки.
                    Intent confirm = intent.getParcelableExtra(Intent.EXTRA_INTENT);
                    if (confirm != null) {
                        confirm.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                        activity.startActivity(confirm);
                    }
                } else if (status != PackageInstaller.STATUS_SUCCESS) {
                    busy = false;
                    if (status != PackageInstaller.STATUS_FAILURE_ABORTED) {
                        toastError("Не удалось установить обновление: "
                                + intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE));
                    }
                }
                // При успехе система сама перезапускает/закрывает приложение.
            }
        };
        IntentFilter f = new IntentFilter(ACTION_RESULT);
        if (Build.VERSION.SDK_INT >= 33) {
            activity.registerReceiver(resultReceiver, f, Context.RECEIVER_NOT_EXPORTED);
        } else {
            activity.registerReceiver(resultReceiver, f);
        }
    }

    private void toastError(String text) {
        android.widget.Toast.makeText(activity, text, android.widget.Toast.LENGTH_LONG).show();
    }
}
