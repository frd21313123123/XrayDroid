package com.xraydroid;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;
import android.net.VpnService;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.os.ParcelFileDescriptor;

import org.json.JSONArray;
import org.json.JSONObject;

/** VPN-сервис (отдельный процесс :vpn). Весь трафик обрабатывает Rust-ядро. */
public class XrayVpnService extends VpnService {
    public static final String ACTION_START = "com.xraydroid.START";
    public static final String ACTION_STOP = "com.xraydroid.STOP";
    public static final String ACTION_STATUS = "com.xraydroid.STATUS";
    public static final String ACTION_QUERY = "com.xraydroid.QUERY";
    private static final String CHANNEL = "vpn";
    private static final int NOTIFY_ID = 1;

    private ParcelFileDescriptor tun;
    private boolean running;
    private String lastError = "";
    private String name = "";
    private long lastUp, lastDown;
    private final Handler handler = new Handler(Looper.getMainLooper());
    private BroadcastReceiver queryReceiver;

    private final Runnable ticker = new Runnable() {
        @Override
        public void run() {
            if (!running) return;
            long[] s = XrayCore.nativeStats();
            long up = s != null ? s[0] : 0, down = s != null ? s[1] : 0;
            String speed = "↑ " + fmt(up - lastUp) + "/с  ↓ " + fmt(down - lastDown) + "/с";
            lastUp = up;
            lastDown = down;
            notifyText(name, speed);
            broadcast();
            handler.postDelayed(this, 1000);
        }
    };

    @Override
    public void onCreate() {
        super.onCreate();
        queryReceiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context c, Intent i) { broadcast(); }
        };
        IntentFilter f = new IntentFilter(ACTION_QUERY);
        if (Build.VERSION.SDK_INT >= 33) registerReceiver(queryReceiver, f, Context.RECEIVER_NOT_EXPORTED);
        else registerReceiver(queryReceiver, f);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent != null ? intent.getAction() : ACTION_START;
        if (ACTION_STOP.equals(action)) {
            stopVpn("");
            return START_NOT_STICKY;
        }
        startVpn();
        return START_STICKY;
    }

    private void startVpn() {
        startInForeground("Подключение…");
        if (running) stopCore();
        lastError = "";
        try {
            JSONObject p = new JSONObject(XrayCore.nativePrepare(getFilesDir().getAbsolutePath()));
            String err = p.optString("error");
            if (!err.isEmpty()) { stopVpn(err); return; }
            name = p.optString("name");
            Builder b = new Builder();
            b.setSession(name);
            b.setMtu(p.optInt("mtu", 1500));
            b.addAddress("172.19.0.1", 30);
            b.addRoute("0.0.0.0", 0);
            b.addDnsServer("172.19.0.2");
            if (p.optBoolean("ipv6", true)) {
                b.addAddress("fdfe:dcba:9876::1", 126);
                b.addRoute("::", 0);
            }
            int mode = p.optInt("mode", 0);
            JSONArray apps = p.optJSONArray("apps");
            boolean allowedAny = false;
            if (mode == 1 && apps != null) {
                for (int i = 0; i < apps.length(); i++) {
                    try { b.addAllowedApplication(apps.getString(i)); allowedAny = true; }
                    catch (PackageManager.NameNotFoundException ignored) {}
                }
            }
            if (!allowedAny) {
                b.addDisallowedApplication(getPackageName());
                if (mode == 2 && apps != null) {
                    for (int i = 0; i < apps.length(); i++) {
                        try { b.addDisallowedApplication(apps.getString(i)); }
                        catch (PackageManager.NameNotFoundException ignored) {}
                    }
                }
            }
            if (Build.VERSION.SDK_INT >= 29) b.setMetered(false);
            b.setConfigureIntent(PendingIntent.getActivity(this, 0,
                    new Intent(this, MainActivity.class), PendingIntent.FLAG_IMMUTABLE));
            tun = b.establish();
            if (tun == null) { stopVpn("не удалось создать VPN-интерфейс"); return; }
            String startErr = XrayCore.nativeStart(tun.getFd());
            if (!startErr.isEmpty()) { stopVpn(startErr); return; }
            running = true;
            lastUp = lastDown = 0;
            notifyText(name, "Подключено");
            broadcast();
            handler.removeCallbacks(ticker);
            handler.postDelayed(ticker, 1000);
        } catch (Exception e) {
            stopVpn(String.valueOf(e.getMessage()));
        }
    }

    private void stopCore() {
        XrayCore.nativeStop();
        if (tun != null) {
            try { tun.close(); } catch (Exception ignored) {}
            tun = null;
        }
    }

    private void stopVpn(String error) {
        handler.removeCallbacks(ticker);
        stopCore();
        running = false;
        lastError = error == null ? "" : error;
        broadcast();
        stopForeground(STOP_FOREGROUND_REMOVE);
        stopSelf();
    }

    @Override
    public void onRevoke() {
        stopVpn("");
    }

    @Override
    public void onDestroy() {
        try { unregisterReceiver(queryReceiver); } catch (Exception ignored) {}
        if (running) {
            handler.removeCallbacks(ticker);
            stopCore();
            running = false;
            broadcast();
        }
        super.onDestroy();
    }

    private void broadcast() {
        long[] s = running ? XrayCore.nativeStats() : null;
        Intent i = new Intent(ACTION_STATUS).setPackage(getPackageName())
                .putExtra("running", running)
                .putExtra("error", lastError)
                .putExtra("up", s != null ? s[0] : 0L)
                .putExtra("down", s != null ? s[1] : 0L);
        sendBroadcast(i);
    }

    private Notification build(String title, String text) {
        NotificationManager nm = getSystemService(NotificationManager.class);
        if (nm.getNotificationChannel(CHANNEL) == null) {
            NotificationChannel ch = new NotificationChannel(CHANNEL, "VPN", NotificationManager.IMPORTANCE_LOW);
            ch.setShowBadge(false);
            nm.createNotificationChannel(ch);
        }
        PendingIntent open = PendingIntent.getActivity(this, 0, new Intent(this, MainActivity.class),
                PendingIntent.FLAG_IMMUTABLE);
        PendingIntent stop = PendingIntent.getService(this, 1,
                new Intent(this, XrayVpnService.class).setAction(ACTION_STOP), PendingIntent.FLAG_IMMUTABLE);
        return new Notification.Builder(this, CHANNEL)
                .setSmallIcon(R.drawable.ic_notification)
                .setContentTitle(title == null || title.isEmpty() ? "XrayDroid" : title)
                .setContentText(text)
                .setContentIntent(open)
                .setOngoing(true)
                .setOnlyAlertOnce(true)
                .addAction(new Notification.Action.Builder(null, "Отключить", stop).build())
                .build();
    }

    private void startInForeground(String text) {
        Notification n = build("XrayDroid", text);
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIFY_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        } else {
            startForeground(NOTIFY_ID, n);
        }
    }

    private void notifyText(String title, String text) {
        getSystemService(NotificationManager.class).notify(NOTIFY_ID, build(title, text));
    }

    private static String fmt(long b) {
        if (b < 0) b = 0;
        if (b < 1024) return b + " Б";
        if (b < 1024 * 1024) return String.format(java.util.Locale.US, "%.1f КБ", b / 1024.0);
        return String.format(java.util.Locale.US, "%.1f МБ", b / 1048576.0);
    }
}
