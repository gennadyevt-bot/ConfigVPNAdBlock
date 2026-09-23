package com.config.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import com.wireguard.android.backend.GoBackend
import java.util.concurrent.CompletableFuture

// Phase C: единый VPN slot для всего приложения.
// wireguard GoBackend не имеет публичного setService(): его вложенный VpnService
// заполняет приватное статическое поле vpnService (CompletableFuture) из
// onCreate/onStartCommand. Мы биндим СВОЙ сервис в это поле раньше, чем
// wgBackend.setState(UP) запросит сервис — тогда библиотека строит TUN через
// НАШ Builder: один VPN interface, один foreground service, один notification.
// AdBlock-слой встанет между TUN и WG на следующих фазах (D/E).
class UnifiedVpnService : android.net.VpnService() {

    companion object {
        const val ACTION_STOP = "com.config.vpnadblock.UNIFIED_STOP"
        private const val CHANNEL_ID = "unified_vpn"
        private const val NOTIF_ID = 1001

        // Рефлексивный bind: GoBackend.vpnService.complete(service).
        // false = future уже занят вложенным сервисом библиотеки (успел раньше)
        // — тогда слот принадлежит ему; подключение всё равно работает.
        fun bindIntoGoBackend(service: android.net.VpnService): Boolean {
            return try {
                val f = GoBackend::class.java.getDeclaredField("vpnService")
                f.isAccessible = true
                @Suppress("UNCHECKED_CAST")
                val future = f.get(null) as CompletableFuture<android.net.VpnService>
                future.complete(service)
            } catch (e: Exception) {
                false
            }
        }
    }

    override fun onCreate() {
        super.onCreate()
        bindIntoGoBackend(this)
        startForegroundWith("VPN подключается…")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        bindIntoGoBackend(this)
        if (intent?.action == ACTION_STOP) {
            stopSelf()
        } else {
            startForegroundWith("VPN активен • AdBlock: не подключён (Phase C)")
        }
        return START_STICKY
    }

    override fun onDestroy() {
        try { stopForeground(true) } catch (_: Exception) {}
        super.onDestroy()
    }

    private fun startForegroundWith(text: String) {
        val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= 26) {
            nm.createNotificationChannel(NotificationChannel(CHANNEL_ID, "VPN", NotificationManager.IMPORTANCE_LOW))
        }
        val pi = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val notification: Notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_menu)
            .setContentTitle("Config VPN + AdBlock")
            .setContentText(text)
            .setContentIntent(pi)
            .setOngoing(true)
            .build()
        startForeground(NOTIF_ID, notification)
    }
}
