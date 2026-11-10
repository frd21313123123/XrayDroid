package com.xraydroid;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.net.Uri;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 * Автообновление: при запуске сверяет версию с последним релизом на GitHub,
 * предлагает обновиться и открывает страницу релиза в браузере. APK приложение само
 * не скачивает и не устанавливает (это вызывает срабатывания Google Play Protect).
 */
final class Updater {
    private static final String REPO = "frd21313123123/XrayDroid";

    private final Activity activity;
    private boolean checked;

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
    }

    // ───── GitHub ─────

    private static final class Release {
        String version;
        String pageUrl;
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
                r.pageUrl = j.optString("html_url", "https://github.com/" + REPO + "/releases/latest");
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
        if (activity.isFinishing()) return;
        String msg = "Доступна новая версия " + r.version.replaceFirst("^[vV]", "")
                + ".\nОткрыть страницу загрузки?";
        new AlertDialog.Builder(activity)
                .setTitle("Доступно обновление")
                .setMessage(msg)
                .setPositiveButton("Открыть", (d, w) -> {
                    try {
                        activity.startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(r.pageUrl)));
                    } catch (Exception ignored) {
                    }
                })
                .setNegativeButton("Позже", null)
                .show();
    }
}
