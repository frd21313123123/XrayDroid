package com.xraydroid;

import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.VpnService;
import android.os.Build;
import android.service.quicksettings.Tile;
import android.service.quicksettings.TileService;

/** Плитка в шторке быстрых настроек: включить/выключить VPN. */
public class QuickTileService extends TileService {
    private boolean running;
    private BroadcastReceiver receiver;

    @Override
    public void onStartListening() {
        receiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context c, Intent i) {
                running = i.getBooleanExtra("running", false);
                update();
            }
        };
        IntentFilter f = new IntentFilter(XrayVpnService.ACTION_STATUS);
        if (Build.VERSION.SDK_INT >= 33) registerReceiver(receiver, f, Context.RECEIVER_NOT_EXPORTED);
        else registerReceiver(receiver, f);
        running = false;
        update();
        sendBroadcast(new Intent(XrayVpnService.ACTION_QUERY).setPackage(getPackageName()));
    }

    @Override
    public void onStopListening() {
        try { unregisterReceiver(receiver); } catch (Exception ignored) {}
    }

    @Override
    public void onClick() {
        if (running) {
            startService(new Intent(this, XrayVpnService.class).setAction(XrayVpnService.ACTION_STOP));
            running = false;
            update();
            return;
        }
        if (VpnService.prepare(this) != null) {
            Intent i = new Intent(this, MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            if (Build.VERSION.SDK_INT >= 34) {
                startActivityAndCollapse(PendingIntent.getActivity(this, 0, i, PendingIntent.FLAG_IMMUTABLE));
            } else {
                startActivityAndCollapse(i);
            }
            return;
        }
        startForegroundService(new Intent(this, XrayVpnService.class).setAction(XrayVpnService.ACTION_START));
    }

    private void update() {
        Tile t = getQsTile();
        if (t == null) return;
        t.setState(running ? Tile.STATE_ACTIVE : Tile.STATE_INACTIVE);
        t.setLabel("XrayDroid");
        t.updateTile();
    }
}
