package com.xraydroid;

import android.Manifest;
import android.app.NativeActivity;
import android.content.BroadcastReceiver;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;

import org.json.JSONArray;

import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/** Окно приложения: интерфейс рисует Rust (Slint), здесь только системные вызовы. */
public class MainActivity extends NativeActivity {
    private static final int REQ_VPN = 1;
    private BroadcastReceiver receiver;
    private Updater updater;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        receiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context c, Intent i) {
                XrayCore.nativeOnStatus(i.getBooleanExtra("running", false),
                        String.valueOf(i.getStringExtra("error") == null ? "" : i.getStringExtra("error")),
                        i.getLongExtra("up", 0), i.getLongExtra("down", 0), i.getLongExtra("started", 0));
            }
        };
        IntentFilter f = new IntentFilter(XrayVpnService.ACTION_STATUS);
        if (Build.VERSION.SDK_INT >= 33) {
            registerReceiver(receiver, f, Context.RECEIVER_NOT_EXPORTED);
            if (checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, 2);
            }
        } else {
            registerReceiver(receiver, f);
        }
        updater = new Updater(this);
        updater.checkOnStart();
    }

    @Override
    protected void onResume() {
        super.onResume();
        queryStatus();
    }

    @Override
    protected void onDestroy() {
        try { unregisterReceiver(receiver); } catch (Exception ignored) {}
        if (updater != null) updater.release();
        super.onDestroy();
        // Интерфейс Slint нельзя повторно инициализировать в том же процессе,
        // поэтому процесс UI завершается вместе с окном (VPN живёт в процессе :vpn).
        if (isFinishing()) android.os.Process.killProcess(android.os.Process.myPid());
    }

    @Override
    public void onBackPressed() {
        moveTaskToBack(true);
    }

    private void queryStatus() {
        sendBroadcast(new Intent(XrayVpnService.ACTION_QUERY).setPackage(getPackageName()));
    }

    // ───── вызывается из Rust ─────

    public void onUiReady() {
        runOnUiThread(this::queryStatus);
    }

    public void startVpn() {
        runOnUiThread(() -> {
            Intent prepare = VpnService.prepare(this);
            if (prepare != null) {
                startActivityForResult(prepare, REQ_VPN);
            } else {
                startVpnService();
            }
        });
    }

    public void stopVpn() {
        runOnUiThread(() -> {
            Intent i = new Intent(this, XrayVpnService.class).setAction(XrayVpnService.ACTION_STOP);
            try {
                startService(i);
            } catch (Exception e) {
                XrayCore.nativeOnStatus(false, "", 0, 0, 0);
            }
        });
    }

    private void startVpnService() {
        Intent i = new Intent(this, XrayVpnService.class).setAction(XrayVpnService.ACTION_START);
        startForegroundService(i);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQ_VPN) {
            if (resultCode == RESULT_OK) {
                startVpnService();
            } else {
                XrayCore.nativeOnStatus(false, "не выдано разрешение на VPN", 0, 0, 0);
            }
        }
    }

    private <T> T onUi(java.util.concurrent.Callable<T> task) {
        AtomicReference<T> out = new AtomicReference<>();
        CountDownLatch latch = new CountDownLatch(1);
        runOnUiThread(() -> {
            try { out.set(task.call()); } catch (Exception ignored) {}
            latch.countDown();
        });
        try { latch.await(3, TimeUnit.SECONDS); } catch (InterruptedException ignored) {}
        return out.get();
    }

    public String getClipboardText() {
        return onUi(() -> {
            ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            ClipData clip = cm.getPrimaryClip();
            if (clip == null || clip.getItemCount() == 0) return "";
            CharSequence t = clip.getItemAt(0).coerceToText(this);
            return t == null ? "" : t.toString();
        });
    }

    public void setClipboardText(String text) {
        runOnUiThread(() -> {
            ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            cm.setPrimaryClip(ClipData.newPlainText("XrayDroid", text));
        });
    }

    /** JSON [[package, label], ...] приложений с доступом в интернет. */
    public String getInstalledAppsJson() {
        PackageManager pm = getPackageManager();
        JSONArray arr = new JSONArray();
        List<PackageInfo> list = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS);
        for (PackageInfo p : list) {
            if (p.packageName.equals(getPackageName())) continue;
            boolean internet = false;
            if (p.requestedPermissions != null) {
                for (String perm : p.requestedPermissions) {
                    if (Manifest.permission.INTERNET.equals(perm)) { internet = true; break; }
                }
            }
            if (!internet) continue;
            ApplicationInfo ai = p.applicationInfo;
            String label = ai != null ? String.valueOf(pm.getApplicationLabel(ai)) : p.packageName;
            JSONArray item = new JSONArray();
            item.put(p.packageName);
            item.put(label);
            arr.put(item);
        }
        return arr.toString();
    }
}
