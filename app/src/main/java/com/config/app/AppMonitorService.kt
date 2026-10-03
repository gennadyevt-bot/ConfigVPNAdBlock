package com.config.app

import android.app.AppOpsManager
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.app.usage.UsageStats
import android.app.usage.UsageStatsManager
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Process
import android.provider.Settings
import android.widget.Toast
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class AppMonitorService : Service() {

    private val handler = Handler(Looper.getMainLooper())
    private val checkInterval = 2000L
    private val disconnectGraceMs = 60_000L  // ушли ненадолго — VPN не рвём (реконнект ~30 сек)
    private var appVpnStorage: AppVpnStorage? = null
    private var lastSelectedPackages: Set<String> = emptySet()
    private var lastExcludedPackages: Set<String> = emptySet()
    private var lastForegroundApp: String = ""
    private var vpnTriggeredByAppMonitor = false
    private var disconnectPending = false
    private var pendingDisconnectRunnable: Runnable? = null

    private val runnable = object : Runnable {
        override fun run() {
            checkForegroundApp()
            checkAppConfigChanges()
            handler.postDelayed(this, checkInterval)
        }
    }

    override fun onCreate() {
        super.onCreate()
        appVpnStorage = AppVpnStorage(this)
        lastSelectedPackages = appVpnStorage?.getSelectedPackages() ?: emptySet()
        lastExcludedPackages = appVpnStorage?.getExcludedPackages() ?: emptySet()
        android.util.Log.d("AppMonitor", "Service created")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForeground(NOTIFICATION_ID, createNotification())
        handler.post(runnable)

        // Авто-подключение при старте сервиса, если выключен и foreground app подходит
        if (VpnManager.globalStatus == VpnStatus.DISCONNECTED) {
            checkForegroundApp()
        }

        android.util.Log.d("AppMonitor", "Service started")
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        super.onDestroy()
        handler.removeCallbacks(runnable)
        pendingDisconnectRunnable?.let { handler.removeCallbacks(it) }
        android.util.Log.d("AppMonitor", "Service destroyed")
    }

    // ==================== FOREGROUND APP DETECTION ====================

    private fun checkForegroundApp() {
        val storage = appVpnStorage ?: return
        if (!storage.isEnabled()) {
            android.util.Log.d("AppMonitor", "App VPN disabled")
            return
        }

        if (!hasUsageStatsPermission()) {
            android.util.Log.w("AppMonitor", "No Usage Stats permission")
            return
        }

        // Соединение развалилось само — флаг «наше» больше не актуален
        if (VpnManager.globalStatus == VpnStatus.ERROR) {
            vpnTriggeredByAppMonitor = false
        }

        val foregroundApp = getForegroundApp() ?: return
        if (foregroundApp != lastForegroundApp) {
            lastForegroundApp = foregroundApp
            android.util.Log.d("AppMonitor", "Foreground app: $foregroundApp")
        }

        val selectedPackages = storage.getSelectedPackages()
        val excludedPackages = storage.getExcludedPackages()

        val shouldConnect = if (selectedPackages.isNotEmpty()) {
            // Include mode: VPN for selected apps only
            selectedPackages.contains(foregroundApp)
        } else if (excludedPackages.isNotEmpty()) {
            // Exclude mode: VPN for all EXCEPT excluded apps
            !excludedPackages.contains(foregroundApp)
        } else {
            false
        }

        android.util.Log.d("AppMonitor", "Should connect: $shouldConnect (fg=$foregroundApp)")

        if (shouldConnect) {
            cancelPendingDisconnect()
            if (VpnManager.globalStatus == VpnStatus.DISCONNECTED || VpnManager.globalStatus == VpnStatus.ERROR) {
                android.util.Log.d("AppMonitor", "Auto-connecting for app: $foregroundApp")
                vpnTriggeredByAppMonitor = true
                autoConnectVpn()
            }
        } else {
            // Отключаем не сразу, а через grace-период: быстрые переключения
            // между приложениями не должны рвать VPN (реконнект ~30 сек).
            if (vpnTriggeredByAppMonitor && VpnManager.globalStatus == VpnStatus.CONNECTED) {
                scheduleDisconnect()
            }
        }
    }

    private fun scheduleDisconnect() {
        if (disconnectPending) return
        disconnectPending = true
        android.util.Log.d("AppMonitor", "Scheduling disconnect in ${disconnectGraceMs / 1000}s")
        val r = Runnable {
            disconnectPending = false
            pendingDisconnectRunnable = null
            val storage = appVpnStorage
            if (storage == null || !storage.isEnabled()) return@Runnable
            val fg = lastForegroundApp
            val stillRelevant = if (storage.getSelectedPackages().isNotEmpty()) {
                storage.getSelectedPackages().contains(fg)
            } else if (storage.getExcludedPackages().isNotEmpty()) {
                !storage.getExcludedPackages().contains(fg)
            } else false
            if (!stillRelevant && vpnTriggeredByAppMonitor && VpnManager.globalStatus == VpnStatus.CONNECTED) {
                android.util.Log.d("AppMonitor", "Grace period over, auto-disconnecting")
                disconnectVpn()
                vpnTriggeredByAppMonitor = false
            }
        }
        pendingDisconnectRunnable = r
        handler.postDelayed(r, disconnectGraceMs)
    }

    private fun cancelPendingDisconnect() {
        if (!disconnectPending) return
        disconnectPending = false
        pendingDisconnectRunnable?.let { handler.removeCallbacks(it) }
        pendingDisconnectRunnable = null
        android.util.Log.d("AppMonitor", "Pending disconnect cancelled")
    }

    private fun getForegroundApp(): String? {
        return try {
            val usm = getSystemService(Context.USAGE_STATS_SERVICE) as UsageStatsManager
            val time = System.currentTimeMillis()
            val stats = usm.queryUsageStats(UsageStatsManager.INTERVAL_DAILY, time - 1000 * 60, time)
            if (stats.isNullOrEmpty()) {
                android.util.Log.w("AppMonitor", "No usage stats available")
                return null
            }
            val recent = stats.maxByOrNull { it.lastTimeUsed }
            recent?.packageName
        } catch (e: Exception) {
            android.util.Log.e("AppMonitor", "getForegroundApp failed: ${e.message}")
            null
        }
    }

    private fun hasUsageStatsPermission(): Boolean {
        val appOps = getSystemService(Context.APP_OPS_SERVICE) as AppOpsManager
        val mode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            appOps.unsafeCheckOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), packageName)
        } else {
            @Suppress("DEPRECATION")
            appOps.checkOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), packageName)
        }
        return mode == AppOpsManager.MODE_ALLOWED
    }

    // ==================== CONFIG CHANGES ====================

    private fun checkAppConfigChanges() {
        val storage = appVpnStorage ?: return
        if (!storage.isEnabled()) return

        val selectedPackages = storage.getSelectedPackages()
        val excludedPackages = storage.getExcludedPackages()

        if (selectedPackages == lastSelectedPackages && excludedPackages == lastExcludedPackages) {
            return
        }

        lastSelectedPackages = selectedPackages
        lastExcludedPackages = excludedPackages

        android.util.Log.d("AppMonitor", "App config changed, reconnecting...")

        if (VpnManager.globalStatus == VpnStatus.CONNECTED) {
            reconnectVpn()
        } else if (VpnManager.globalStatus == VpnStatus.DISCONNECTED) {
            checkForegroundApp()
        }
    }

    // ==================== VPN ACTIONS ====================

    private fun autoConnectVpn() {
        val servers = EmbeddedServers.all(this)
        val serverId = AppVpnStorage(this).getServerId()
        // Сначала конфиг, выбранный в App VPN, иначе первый валидный
        val validServer = servers.firstOrNull {
            it.id == serverId && it.interfacePrivateKey.isNotEmpty() && it.peerPublicKey.isNotEmpty() && it.peerEndpoint.isNotEmpty()
        } ?: servers.firstOrNull {
            it.interfacePrivateKey.isNotEmpty() && it.peerPublicKey.isNotEmpty() && it.peerEndpoint.isNotEmpty()
        }
        validServer?.let { server ->
            CoroutineScope(Dispatchers.IO).launch {
                try {
                    android.util.Log.d("AppMonitor", "Auto-connecting to ${server.name}...")
                    val vpnManager = VpnManager.getInstance(this@AppMonitorService)
                    vpnManager.connect(server)
                    Handler(Looper.getMainLooper()).post {
                        Toast.makeText(this@AppMonitorService, "VPN автоматически включён", Toast.LENGTH_SHORT).show()
                    }
                } catch (e: Exception) {
                    android.util.Log.e("AppMonitor", "Auto-connect failed: ${e.message}", e)
                }
            }
        }
    }

    private fun disconnectVpn() {
        CoroutineScope(Dispatchers.IO).launch {
            try {
                android.util.Log.d("AppMonitor", "Auto-disconnecting...")
                val vpnManager = VpnManager.getInstance(this@AppMonitorService)
                vpnManager.disconnect()
                Handler(Looper.getMainLooper()).post {
                    Toast.makeText(this@AppMonitorService, "VPN автоматически отключён", Toast.LENGTH_SHORT).show()
                }
            } catch (e: Exception) {
                android.util.Log.e("AppMonitor", "Disconnect failed: ${e.message}", e)
            }
        }
    }

    private fun reconnectVpn() {
        val vpnManager = VpnManager.getInstance(this)
        val currentServer = vpnManager.getCurrentServer() ?: return

        CoroutineScope(Dispatchers.IO).launch {
            try {
                android.util.Log.d("AppMonitor", "Disconnecting for reconnect...")
                vpnManager.disconnect()
                kotlinx.coroutines.delay(500)
                android.util.Log.d("AppMonitor", "Connecting with new app config...")
                vpnManager.connect(currentServer)
                Handler(Looper.getMainLooper()).post {
                    Toast.makeText(this@AppMonitorService, "Конфиг split tunneling обновлён", Toast.LENGTH_SHORT).show()
                }
            } catch (e: Exception) {
                android.util.Log.e("AppMonitor", "Reconnect failed: ${e.message}", e)
            }
        }
    }

    // ==================== NOTIFICATION ====================

    private fun createNotification(): Notification {
        // Новый канал с IMPORTANCE_MIN: иконка App VPN не мозолит строку
        // состояния, уведомление живёт только в шторке (сервис при этом
        // остаётся foreground — система его не убьёт).
        val channelId = "app_monitor_channel_v2"
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(channelId, "App VPN Monitor", NotificationManager.IMPORTANCE_MIN)
            val nm = getSystemService(NotificationManager::class.java)
            nm.createNotificationChannel(channel)
        }
        val intent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP
        }
        val pendingIntent = PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        return NotificationCompat.Builder(this, channelId)
            .setContentTitle("Config VPN")
            .setContentText("Smart App VPN активен — split tunneling")
            .setSmallIcon(android.R.drawable.ic_menu_mylocation)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()
    }

    companion object {
        private const val NOTIFICATION_ID = 1001
        fun start(context: Context) {
            val intent = Intent(context, AppMonitorService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }
        fun stop(context: Context) {
            context.stopService(Intent(context, AppMonitorService::class.java))
        }
    }
}
