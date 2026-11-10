package com.xraydroid;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.VpnService;

/**
 * Две роли: принимает результат установки от PackageInstaller и — уже в новой версии —
 * событие MY_PACKAGE_REPLACED, после которого возвращает VPN и окно приложения.
 */
public class UpdateReceiver extends BroadcastReceiver {
    static final int NOTIFY_ID = 2;
    private static final String CHANNEL = "update";
    /** Обновление «наше», если пакет заменён вскоре после начала установки. */
    private static final long PENDING_TTL_MS = 15 * 60_000L;

    @Override
    public void onReceive(Context context, Intent intent) {
        String action = intent.getAction();
        if (Updater.ACTION_RESULT.equals(action)) {
            Updater u = Updater.instance;
            if (u != null) u.onInstallResult(intent);
        } else if (Intent.ACTION_MY_PACKAGE_REPLACED.equals(action)) {
            onReplaced(context);
        }
    }

    private void onReplaced(Context context) {
        SharedPreferences prefs = context.getSharedPreferences(Updater.PREFS, Context.MODE_PRIVATE);
        long at = prefs.getLong(Updater.KEY_PENDING_AT, 0);
        if (at == 0) return; // пакет заменили не мы (ручная установка, adb)
        boolean vpn = prefs.getBoolean(Updater.KEY_VPN, false);
        String version = prefs.getString(Updater.KEY_VERSION, "");
        prefs.edit().remove(Updater.KEY_PENDING_AT).apply();
        long age = System.currentTimeMillis() - at;
        if (age < 0 || age > PENDING_TTL_MS) return;

        // VPN был включён до обновления — поднимаем его сразу. Запуск foreground-сервиса
        // из MY_PACKAGE_REPLACED разрешён системой, разрешение на VPN обновление переживает.
        if (vpn) {
            try {
                if (VpnService.prepare(context) == null) {
                    context.startForegroundService(new Intent(context, XrayVpnService.class)
                            .setAction(XrayVpnService.ACTION_START));
                }
            } catch (Exception ignored) {
            }
        }

        // Окно: Android 10+ может не дать открыть его из фона, поэтому есть и уведомление —
        // MainActivity убирает его при запуске.
        Intent open = new Intent(context, MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        notifyUpdated(context, open, version, vpn);
        try {
            context.startActivity(open);
        } catch (Exception ignored) {
        }
    }

    private static void notifyUpdated(Context context, Intent open, String version, boolean vpn) {
        try {
            NotificationManager nm = context.getSystemService(NotificationManager.class);
            if (nm.getNotificationChannel(CHANNEL) == null) {
                nm.createNotificationChannel(new NotificationChannel(CHANNEL, "Обновления",
                        NotificationManager.IMPORTANCE_DEFAULT));
            }
            PendingIntent pi = PendingIntent.getActivity(context, 2, open, PendingIntent.FLAG_IMMUTABLE);
            nm.notify(NOTIFY_ID, new Notification.Builder(context, CHANNEL)
                    .setSmallIcon(R.drawable.ic_notification)
                    .setContentTitle("XrayDroid обновлён" + (version.isEmpty() ? "" : " до " + version))
                    .setContentText(vpn ? "VPN подключается заново. Нажмите, чтобы открыть."
                            : "Нажмите, чтобы открыть приложение.")
                    .setContentIntent(pi)
                    .setAutoCancel(true)
                    .build());
        } catch (Exception ignored) {
        }
    }
}
