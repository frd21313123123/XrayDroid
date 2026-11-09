package com.xraydroid;

/** Мост к Rust-библиотеке libxraydroid.so. */
public final class XrayCore {
    static {
        System.loadLibrary("xraydroid");
    }

    private XrayCore() {}

    /** Процесс VPN: читает config.json, возвращает JSON-параметры интерфейса. */
    public static native String nativePrepare(String filesDir);

    /** Процесс VPN: запускает ядро на дескрипторе TUN. Пустая строка — успех. */
    public static native String nativeStart(int fd);

    public static native void nativeStop();

    /** [отправлено, получено] байт. */
    public static native long[] nativeStats();

    /** Процесс UI: статус от сервиса. */
    public static native void nativeOnStatus(boolean running, String error, long up, long down);
}
