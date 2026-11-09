package com.xraydroid;

import android.content.Context;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.os.Build;
import android.system.OsConstants;

import java.net.InetAddress;
import java.net.InetSocketAddress;

/** Мост к Rust-библиотеке libxraydroid.so. */
public final class XrayCore {
    static {
        System.loadLibrary("xraydroid");
    }

    private static volatile ConnectivityManager cm;
    private static volatile PackageManager pm;

    private XrayCore() {}

    /** Процесс VPN: системные сервисы для определения приложения по соединению. */
    public static void init(Context c) {
        cm = c.getSystemService(ConnectivityManager.class);
        pm = c.getPackageManager();
    }

    /** Вызывается из Rust: UID владельца соединения или -1 (нужен Android 10+). */
    public static int ownerUid(int proto, String srcIp, int srcPort, String dstIp, int dstPort) {
        ConnectivityManager m = cm;
        if (m == null || Build.VERSION.SDK_INT < 29) return -1;
        try {
            int p = proto == 6 ? OsConstants.IPPROTO_TCP : OsConstants.IPPROTO_UDP;
            return m.getConnectionOwnerUid(p,
                    new InetSocketAddress(InetAddress.getByName(srcIp), srcPort),
                    new InetSocketAddress(InetAddress.getByName(dstIp), dstPort));
        } catch (Throwable t) {
            return -1;
        }
    }

    /** Вызывается из Rust: UID установленного приложения или -1. */
    public static int packageUid(String pkg) {
        PackageManager m = pm;
        if (m == null) return -1;
        try {
            return m.getApplicationInfo(pkg, 0).uid;
        } catch (Throwable t) {
            return -1;
        }
    }

    /** Процесс VPN: читает config.json, возвращает JSON-параметры интерфейса. */
    public static native String nativePrepare(String filesDir);

    /** Процесс VPN: запускает ядро на дескрипторе TUN. Пустая строка — успех. */
    public static native String nativeStart(int fd);

    public static native void nativeStop();

    /** [отправлено, получено] байт. */
    public static native long[] nativeStats();

    /** Процесс UI: статус от сервиса. */
    public static native void nativeOnStatus(boolean running, String error, long up, long down, long startedMs);
}
