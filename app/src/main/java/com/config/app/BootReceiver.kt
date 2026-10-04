package com.config.app

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.util.Log

class BootReceiver : BroadcastReceiver() {
    companion object {
        private const val TAG = "BootReceiver"
    }

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED) {
            Log.i(TAG, "Boot completed — checking VPN state")

            val vpnStateStorage = VpnStateStorage(context)
            val autoStorage = AutoConnectStorage(context)

            // Если VPN был включен до перезагрузки — восстанавливаем
            if (vpnStateStorage.wasConnected()) {
                Log.i(TAG, "VPN was connected before reboot — starting keep-alive service")
                val serviceIntent = Intent(context, VpnKeepAliveService::class.java)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    context.startForegroundService(serviceIntent)
                } else {
                    context.startService(serviceIntent)
                }
            }

            // Если включено автоподключение по приложениям
            if (autoStorage.isEnabled()) {
                Log.i(TAG, "Auto-connect enabled — starting monitoring")
                val serviceIntent = Intent(context, VpnKeepAliveService::class.java).apply {
                    putExtra("auto_connect", true)
                }
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    context.startForegroundService(serviceIntent)
                } else {
                    context.startService(serviceIntent)
                }
            }
        }
    }
}
