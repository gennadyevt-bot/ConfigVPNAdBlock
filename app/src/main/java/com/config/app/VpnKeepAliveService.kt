package com.config.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.util.Log
import androidx.core.app.NotificationCompat

class VpnKeepAliveService : Service() {

    companion object {
        private const val TAG = "VpnKeepAlive"
        private const val NOTIF_ID = 1001
        private const val CHANNEL_ID = "config_vpn_keepalive"
        private const val CHANNEL_ID_MIN = "config_vpn_keepalive_min"
        private const val CHECK_INTERVAL = 5000L
    }

    private val handler = Handler(Looper.getMainLooper())
    private var checkRunnable: Runnable? = null
    private var vpnManager: VpnManager? = null
    private var serverStorage: ServerStorage? = null
    private var vpnStateStorage: VpnStateStorage? = null

    override fun onCreate() {
        super.onCreate()
        Log.i(TAG, "Service created")
        vpnManager = VpnManager.getInstance(this)
        serverStorage = ServerStorage(this)
        vpnStateStorage = VpnStateStorage(this)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.i(TAG, "Service started")
        startForeground(NOTIF_ID, buildNotification())

        // Восстанавливаем VPN если был подключен
        if (vpnStateStorage?.wasConnected() == true && vpnManager?.getStatus() == VpnStatus.DISCONNECTED) {
            val lastServerId = vpnStateStorage?.getLastServer()
            val servers = serverStorage?.loadServers() ?: emptyList()
            val server = servers.find { it.id == lastServerId } ?: servers.firstOrNull { 
                it.interfacePrivateKey.isNotEmpty() && it.peerPublicKey.isNotEmpty() && it.peerEndpoint.isNotEmpty()
            }

            server?.let {
                Log.i(TAG, "Restoring VPN connection to ${it.name}")
                vpnManager?.connect(it)
            }
        }

        // Repeated startService calls must not accumulate reconnect timers.
        checkRunnable?.let { handler.removeCallbacks(it) }
        statusTicker?.let { handler.removeCallbacks(it) }
        // Периодическая проверка — переподключаем если VPN упал
        startKeepAliveCheck()
        // Ненавязчивый индикатор: текст уведомления показывает прогресс подключения
        startStatusTicker()

        return START_STICKY
    }

    private var connectStartMs = 0L
    private var lastSeenStatus: VpnStatus = VpnStatus.DISCONNECTED
    private var statusTicker: Runnable? = null

    private fun startStatusTicker() {
        statusTicker = object : Runnable {
            override fun run() {
                val status = vpnManager?.getStatus() ?: VpnStatus.DISCONNECTED
                if (status == VpnStatus.CONNECTING && lastSeenStatus != VpnStatus.CONNECTING) {
                    connectStartMs = System.currentTimeMillis()
                }
                lastSeenStatus = status
                val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
                val text = when (status) {
                    VpnStatus.CONNECTING -> {
                        val secs = (System.currentTimeMillis() - connectStartMs) / 1000
                        // Индикатор с задержкой: первые 5 секунд — короткий текст,
                        // счётчик появляется только когда подключение затянулось.
                        if (secs < 5) "Подключение…"
                        else "Подключение… ${secs} сек (это нормально, ждите)"
                    }
                    VpnStatus.CONNECTED -> "VPN подключён"
                    else -> "Мониторинг VPN подключения"
                }
                nm.notify(NOTIF_ID, buildNotification(text))
                handler.postDelayed(this, 1000)
            }
        }
        handler.post(statusTicker!!)
    }

    private fun startKeepAliveCheck() {
        checkRunnable = object : Runnable {
            override fun run() {
                if (vpnStateStorage?.wasConnected() == true && vpnManager?.getStatus() == VpnStatus.DISCONNECTED) {
                    val lastServerId = vpnStateStorage?.getLastServer()
                    val servers = serverStorage?.loadServers() ?: emptyList()
                    val server = servers.find { it.id == lastServerId } ?: servers.firstOrNull { 
                        it.interfacePrivateKey.isNotEmpty() && it.peerPublicKey.isNotEmpty() && it.peerEndpoint.isNotEmpty()
                    }
                    server?.let {
                        Log.i(TAG, "VPN disconnected unexpectedly — reconnecting to ${it.name}")
                        vpnManager?.connect(it)
                    }
                }
                handler.postDelayed(this, CHECK_INTERVAL)
            }
        }
        handler.post(checkRunnable!!)
    }

    private fun appVpnMode(): Boolean {
        val s = AppVpnStorage(this)
        return s.isEnabled() && s.getSelectedPackages().isNotEmpty()
    }

    private fun buildNotification(text: String = "Мониторинг VPN подключения"): Notification {
        val appVpn = appVpnMode()
        createNotificationChannel(appVpn)
        val channelId = if (appVpn) CHANNEL_ID_MIN else CHANNEL_ID

        // В режиме App VPN — минимум текста: пользователь просил не показывать
        // «VPN подключён», когда работает автоматическая маршрутизация по приложениям.
        val shownText = if (appVpn && vpnManager?.getStatus() == VpnStatus.CONNECTED) {
            "App VPN работает"
        } else text

        val intent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP
        }
        val pendingIntent = PendingIntent.getActivity(
            this, 0, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, channelId)
            .setContentTitle("Config VPN")
            .setContentText(shownText)
            .setSmallIcon(android.R.drawable.ic_lock_idle_lock)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()
    }

    private fun createNotificationChannel(appVpn: Boolean) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            // Отдельный тихий канал для режима App VPN: IMPORTANCE_MIN —
            // без иконки в строке состояния, только в шторке.
            val channel = if (appVpn) {
                NotificationChannel(
                    CHANNEL_ID_MIN,
                    "Config VPN (App VPN)",
                    NotificationManager.IMPORTANCE_MIN
                ).apply {
                    description = "Фоновая работа App VPN"
                    setShowBadge(false)
                }
            } else {
                NotificationChannel(
                    CHANNEL_ID,
                    "Config VPN Keep-Alive",
                    NotificationManager.IMPORTANCE_LOW
                ).apply {
                    description = "Фоновый мониторинг VPN"
                    setShowBadge(false)
                }
            }
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        super.onDestroy()
        checkRunnable?.let { handler.removeCallbacks(it) }
        statusTicker?.let { handler.removeCallbacks(it) }
        Log.i(TAG, "Service destroyed")
    }
}
