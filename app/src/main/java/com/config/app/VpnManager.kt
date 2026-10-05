package com.config.app

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.widget.Toast
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.util.concurrent.atomic.AtomicLong
import com.wireguard.android.backend.Backend as WgBackend
import com.wireguard.android.backend.GoBackend as WgGoBackend
import com.wireguard.android.backend.Tunnel as WgBackendTunnel
import com.wireguard.config.Config as WgConfig
import org.amnezia.awg.backend.Backend as AwgBackend
import org.amnezia.awg.backend.GoBackend as AwgGoBackend
import org.amnezia.awg.backend.NoopTunnelActionHandler
import org.amnezia.awg.backend.Tunnel as AwgBackendTunnel
import org.amnezia.awg.config.Config as AwgConfig
import java.io.ByteArrayInputStream

class VpnManager private constructor(private val context: Context) {

    private val wgBackend: WgBackend = WgGoBackend(context.applicationContext)

    // Both protocols use UnifiedVpnService's application scope when AdBlock is on.
    private val awgBackend: AwgBackend = AwgGoBackend(context.applicationContext, NoopTunnelActionHandler())

    private var currentWgConfig: WgConfig? = null
    private var currentAwgConfig: AwgConfig? = null
    private var usingAwg = false
    private val vpnStateStorage = VpnStateStorage(context)

    var onStatusChanged: ((VpnStatus) -> Unit)? = null
    var onServerChanged: ((ServerInfo?) -> Unit)? = null

    private var currentServer: ServerInfo? = null
    private val scope = CoroutineScope(Dispatchers.IO)
    private val lifecycleMutex = Mutex()
    private val lifecycleRequests = AtomicLong()

    private fun dbg(msg: String) {
        try {
            val f = java.io.File(context.filesDir, "debug.log")
            f.appendText(java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.US).format(java.util.Date()) + " " + msg + "\n")
            if (f.length() > 200000) f.writeText(f.readText().takeLast(100000))
        } catch (_: Exception) {}
    }

    fun getPrepareIntent(activity: Activity): android.content.Intent? {
        return VpnService.prepare(activity)
    }

    fun isPrepared(): Boolean {
        return VpnService.prepare(context) == null
    }

    fun connect(server: ServerInfo) {
        val request = lifecycleRequests.incrementAndGet()
        scope.launch {
            lifecycleMutex.withLock {
                if (request == lifecycleRequests.get()) {
                    val appPrefs = AppVpnStorage(context)
                    val target = if (appPrefs.isEnabled()) {
                        EmbeddedServers.all(context).firstOrNull { it.id == appPrefs.getServerId() } ?: server
                    } else server
                    connectLocked(target, false, request)
                }
            }
        }
    }

    fun reapplyAppVpnScope() {
        // Do not queue a connection for an off/disconnecting session. The request
        // token also invalidates a queued rebuild immediately on manual STOP.
        if (!vpnStateStorage.wasConnected() ||
            (globalStatus != VpnStatus.CONNECTED && globalStatus != VpnStatus.CONNECTING)) return
        val request = lifecycleRequests.get()
        scope.launch {
            lifecycleMutex.withLock {
                if (request != lifecycleRequests.get() || !vpnStateStorage.wasConnected() ||
                    globalStatus != VpnStatus.CONNECTED) return@withLock
                val current = currentServer ?: return@withLock
                val appPrefs = AppVpnStorage(context)
                val target = if (appPrefs.isEnabled()) {
                    EmbeddedServers.all(context).firstOrNull { it.id == appPrefs.getServerId() } ?: current
                } else current
                connectLocked(target, true, request)
            }
        }
    }

    private suspend fun connectLocked(server: ServerInfo, forceRebuild: Boolean, request: Long) {
        try {
            val prepareIntent = VpnService.prepare(context)
            if (prepareIntent != null) {
                withContext(Dispatchers.Main) {
                    updateStatus(VpnStatus.ERROR)
                    showToast("Ошибка: разрешение VPN не дано. Откройте приложение и нажмите CONNECT.")
                }
                return
            }

            currentServer = server
            withContext(Dispatchers.Main) {
                onServerChanged?.invoke(server)
                updateStatus(VpnStatus.CONNECTING)
            }

            if (request != lifecycleRequests.get()) return
            vpnStateStorage.setWasConnected(true)
            vpnStateStorage.setLastServer(server.id)

            val serviceIntent = Intent(context, VpnKeepAliveService::class.java)
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                context.startForegroundService(serviceIntent)
            } else {
                context.startService(serviceIntent)
            }

            val appPrefs = AppVpnStorage(context)
            val includedApps = if (appPrefs.isEnabled()) appPrefs.getSelectedPackages().toList() else emptyList()
            val excludedApps = if (appPrefs.isEnabled() && includedApps.isEmpty()) appPrefs.getExcludedPackages().toList() else emptyList()
            if (forceRebuild && !UnifiedVpnService.active) {
                if (usingAwg) awgBackend.setState(AwgTunnel.getInstance(), AwgBackendTunnel.State.DOWN, currentAwgConfig)
                else wgBackend.setState(WgTunnel.getInstance(), WgBackendTunnel.State.DOWN, currentWgConfig)
            }

            // Конфиг с junk-параметрами (AmneziaWG) идёт через AWG-бэкенд —
            // он обходит DPI РНК. Обычные конфиги — через WireGuard с App VPN.
            val wantsAwg = server.jc.isNotEmpty() && server.jc != "0"
            if (wantsAwg) {
                connectAwg(server, includedApps, excludedApps, forceRebuild)
            } else {
                connectWg(server, includedApps, excludedApps, forceRebuild)
            }

            withContext(Dispatchers.Main) {
                if (request != lifecycleRequests.get()) return@withContext
                if (context.getSharedPreferences("app_prefs", Context.MODE_PRIVATE)
                        .getBoolean("adblock_enabled", false) &&
                    (!UnifiedVpnService.active || !UnifiedAdBlock.ready)) {
                    throw IllegalStateException("AdBlock остановился во время подключения")
                }
                updateStatus(VpnStatus.CONNECTED)
                StopVpnWidget.updateWidget(context, VpnStatus.CONNECTED)
            }
        } catch (e: Exception) {
            if (request != lifecycleRequests.get()) return
            val err = e.message ?: e.toString()
            android.util.Log.e("ConfigVPN", "Connect failed", e)
            vpnStateStorage.setWasConnected(false)
            withContext(Dispatchers.Main) {
                updateStatus(VpnStatus.ERROR)
                StopVpnWidget.updateWidget(context, VpnStatus.ERROR)
                showToast("Ошибка: $err")
            }
        }
    }

    private suspend fun connectWg(server: ServerInfo, includedApps: List<String>, excludedApps: List<String>, forceRebuild: Boolean) {
        val configString = buildConfigString(server, includedApps, excludedApps, withAwg = false)

        val config = WgConfig.parse(ByteArrayInputStream(configString.toByteArray()))
        currentWgConfig = config
        usingAwg = false

        val tunnel = WgTunnel.getInstance()
        // Phase C: единый VPN slot — наш foreground-сервис биндится в GoBackend
        // до setState, TUN строится через его Builder (single interface).
        context.startForegroundService(Intent(context, UnifiedVpnService::class.java))
        // AdBlock ON: Android TUN → фильтр → WG/AWG packet engine.
        // При ошибке фильтра подключение завершается с явной ошибкой.
        if (context.getSharedPreferences("app_prefs", Context.MODE_PRIVATE).getBoolean("adblock_enabled", false)) {
            val adOk = UnifiedVpnService.connectAdBlockBlocking(context, server, forceRebuild = forceRebuild)
            if (adOk) {
                dbg("ADBLOCK: ACTIVE")
                probePaths()
                return
            }
            throw IllegalStateException("AdBlock не запущен. Откройте журнал AdBlock")
        }
        val t0 = System.currentTimeMillis()
        wgBackend.setState(tunnel, WgBackendTunnel.State.UP, config)
        publishBackendScope(config.`interface`.includedApplications.toList(), config.`interface`.excludedApplications.toList())
        android.util.Log.d("ConfigVPN", "WG handshake: ${System.currentTimeMillis() - t0} ms")
        dbg("WG up: " + (System.currentTimeMillis() - t0) + " ms")

        warnIfNoTraffic {
            runCatching { wgBackend.getStatistics(tunnel).totalRx() }.getOrNull()
        }
        probePaths()
    }

    private suspend fun connectAwg(server: ServerInfo, includedApps: List<String>, excludedApps: List<String>, forceRebuild: Boolean) {
        try {
            val configString = buildConfigString(server, includedApps, excludedApps, withAwg = true)

            val config = AwgConfig.parse(ByteArrayInputStream(configString.toByteArray()))
            currentAwgConfig = config
            usingAwg = true

            if (context.getSharedPreferences("app_prefs", Context.MODE_PRIVATE).getBoolean("adblock_enabled", false)) {
                context.startForegroundService(Intent(context, UnifiedVpnService::class.java))
                val adOk = UnifiedVpnService.connectAdBlockBlocking(context, server, awg = true, forceRebuild = forceRebuild)
                if (adOk) {
                    dbg("ADBLOCK: AWG datapath active")
                    return
                }
                throw IllegalStateException("AdBlock не запущен. Откройте журнал AdBlock")
            }

            val t0 = System.currentTimeMillis()
            awgBackend.setState(AwgTunnel.getInstance(), AwgBackendTunnel.State.UP, config)
            publishBackendScope(config.`interface`.includedApplications.toList(), config.`interface`.excludedApplications.toList())
            android.util.Log.d("ConfigVPN", "AWG handshake: ${System.currentTimeMillis() - t0} ms")

            warnIfNoTraffic {
                runCatching { awgBackend.getStatistics(AwgTunnel.getInstance()).totalRx() }.getOrNull()
            }
            probePaths()
        } catch (e: Exception) {
            if (context.getSharedPreferences("app_prefs", Context.MODE_PRIVATE).getBoolean("adblock_enabled", false)) throw e
            // Фолбэк: сервер не принял junk-параметры — пробуем обычный WireGuard
            android.util.Log.w("ConfigVPN", "AWG failed, falling back to plain WireGuard", e)
            dbg("AWG FAILED: " + (e.stackTraceToString() ?: e.toString()).take(1500))
            connectWg(server, includedApps, excludedApps, forceRebuild)
        }
    }

    // Диагностика: VPN-интерфейс поднят, но сервер молчит (конфиг устарел
    // или IP заблокирован) — иначе получается «без ошибок, но интернета нет».
    private fun warnIfNoTraffic(rxProvider: () -> Long?) {
        scope.launch {
            delay(10000)
            val rx = rxProvider() ?: return@launch
            if (rx == 0L && globalStatus == VpnStatus.CONNECTED) {
                withContext(Dispatchers.Main) {
                    showToast("⚠️ Сервер не отвечает 10 сек: конфиг устарел или IP заблокирован. Попробуйте другой сервер.")
                }
            }
        }
    }

    fun disconnect() {
        lifecycleRequests.incrementAndGet()
        vpnStateStorage.setWasConnected(false)
        context.stopService(Intent(context, VpnKeepAliveService::class.java))
        scope.launch {
            lifecycleMutex.withLock {
                try {
                    withContext(Dispatchers.Main) {
                        updateStatus(VpnStatus.DISCONNECTING)
                    }

                    // Recheck after any in-flight connect has released the mutex.
                    vpnStateStorage.setWasConnected(false)
                    context.stopService(Intent(context, VpnKeepAliveService::class.java))
                    if (usingAwg) {
                        awgBackend.setState(AwgTunnel.getInstance(), AwgBackendTunnel.State.DOWN, currentAwgConfig)
                    } else {
                        wgBackend.setState(WgTunnel.getInstance(), WgBackendTunnel.State.DOWN, currentWgConfig)
                    }
                    // Phase C: гасим unified-сервис после разрыва туннеля
                    context.startService(Intent(context, UnifiedVpnService::class.java).setAction(UnifiedVpnService.ACTION_STOP))
                    withContext(Dispatchers.Main) {
                        updateStatus(VpnStatus.DISCONNECTED)
                        currentServer = null
                        onServerChanged?.invoke(null)
                        StopVpnWidget.updateWidget(context, VpnStatus.DISCONNECTED)
                    }
                } catch (e: Exception) {
                    val err = e.message ?: e.toString()
                    android.util.Log.e("ConfigVPN", "Disconnect failed", e)
                    withContext(Dispatchers.Main) {
                        updateStatus(VpnStatus.ERROR)
                        StopVpnWidget.updateWidget(context, VpnStatus.ERROR)
                        showToast("Ошибка: $err")
                    }
                }
            }
        }
    }

    // Called on the main thread by the service. KeepAlive can now see an
    // unexpected loss and restore the saved session instead of trusting stale UI.
    fun onUnifiedStopped(reason: String) {
        AdBlockLog.add("VPN_DATAPATH_STOPPED reason=$reason status=$globalStatus")
        if (globalStatus == VpnStatus.CONNECTED) {
            updateStatus(VpnStatus.DISCONNECTED)
            StopVpnWidget.updateWidget(context, VpnStatus.DISCONNECTED)
        }
    }

    fun getStatus(): VpnStatus = globalStatus
    fun getCurrentServer(): ServerInfo? = currentServer

    private fun hasIPv6Address(address: String): Boolean {
        return address.split(',').any { it.trim().contains(':') }
    }

    private fun sanitizeDns(dns: String, interfaceAddress: String): String {
        val entries = dns.split(',').map { it.trim() }.filter { it.isNotEmpty() }
        val v6 = hasIPv6Address(interfaceAddress)
        val cleaned = entries.filter { !it.contains(':') || v6 }
        return if (cleaned.isEmpty()) "1.1.1.1" else cleaned.joinToString(", ")
    }

    // Замер путей после подключения: TCP-connect к 1.1.1.1 (контроль) и к
    // датацентрам Telegram (149.154.167.50, 91.108.56.130). Каждый результат —
    // ОТДЕЛЬНЫЙ короткий тост (длинный обрезается Android, цифры не видно).
    // По ним видно, где теряется время: туннель до интернета или путь до DC.
    private fun probePaths() {
        scope.launch {
            val targets = listOf(
                Triple("1.1.1.1", 443, "интернет"),
                Triple("149.154.167.50", 443, "Telegram DC1"),
                Triple("91.108.56.130", 443, "Telegram DC2"),
                Triple("2001:67c:4e8:f002::a", 443, "Telegram IPv6")
            )
            for ((ip, port, name) in targets) {
                delay(1200)
                val t0 = System.currentTimeMillis()
                val ms = try {
                    java.net.Socket().use { s ->
                        s.connect(java.net.InetSocketAddress(ip, port), 10000)
                    }
                    System.currentTimeMillis() - t0
                } catch (e: Exception) {
                    -1L
                }
                val line = if (ms < 0) "$name: нет ответа" else "$name: $ms мс"
                android.util.Log.d("ConfigVPN", "probe: $line")
                // тосты со временем скрыты по запросу (мешают на главном экране)
            }
        }
    }

    // Итоговый набор маршрутов (buildAllowedIPs):
    // 1) IPv4: как в конфиге. Telegram в РФ ЗАБЛОКИРОВАН провайдером — его
    //    трафик обязан идти через туннель, исключать DC нельзя (опыт 5.0.3:
    //    «Telegram полностью отказал» — напрямую он умирает в блоке РНК).
    // 2) IPv6: для full-tunnel (0.0.0.0/0) добавляем ::/0 — иначе на
    //    мобильных сетях оператора v6-трафик (YouTube, ChatGPT, браузер)
    //    уходит напрямую мимо VPN. Split-tunnel конфиги не трогаем.

    companion object {
        var globalStatus: VpnStatus = VpnStatus.DISCONNECTED
        @Volatile var backendAppScope: AppliedTunAppScope? = null
            private set

        @Volatile
        private var instance: VpnManager? = null

        fun getInstance(context: Context): VpnManager {
            return instance ?: synchronized(this) {
                instance ?: VpnManager(context.applicationContext).also { instance = it }
            }
        }

        fun destroyInstance() {
            instance = null
        }

        fun buildAllowedIPs(server: ServerInfo): String {
            val entries = server.peerAllowedIPs.split(",").map { it.trim() }.filter { it.isNotEmpty() }
            val out = entries.toMutableList()
            // Full-tunnel перехватывает и IPv6: на мобильных сетях иначе v6 уходит мимо VPN
            val isFullTunnel = entries.any { it == "0.0.0.0/0" }
            if (isFullTunnel && !out.contains("::/0")) out.add("::/0")
            if (out.isEmpty()) out.add("0.0.0.0/0")
            return out.joinToString(", ")
        }
    }

    private fun buildConfigString(server: ServerInfo, includedApps: List<String> = emptyList(), excludedApps: List<String> = emptyList(), withAwg: Boolean = false): String {
        val allowedIPs = buildAllowedIPs(server)
        val dns = sanitizeDns(server.interfaceDns, server.interfaceAddress)
        return buildString {
            appendLine("[Interface]")
            appendLine("Address = ${server.interfaceAddress}")
            appendLine("DNS = $dns")
            appendLine("PrivateKey = ${server.interfacePrivateKey}")
            if (server.interfaceMtu.isNotEmpty()) appendLine("MTU = ${server.interfaceMtu}")

            if (withAwg) {
                // Junk-параметры AmneziaWG — маскируют WireGuard от DPI (обход блокировок РНК)
                if (server.jc.isNotEmpty() && server.jc != "0") appendLine("Jc = ${server.jc}")
                if (server.jmin.isNotEmpty() && server.jmin != "0") appendLine("Jmin = ${server.jmin}")
                if (server.jmax.isNotEmpty() && server.jmax != "0") appendLine("Jmax = ${server.jmax}")
                if (server.s1.isNotEmpty()) appendLine("S1 = ${server.s1}")
                if (server.s2.isNotEmpty()) appendLine("S2 = ${server.s2}")
                if (server.h1.isNotEmpty() && server.h1 != "0") appendLine("H1 = ${server.h1}")
                if (server.h2.isNotEmpty() && server.h2 != "0") appendLine("H2 = ${server.h2}")
                if (server.h3.isNotEmpty() && server.h3 != "0") appendLine("H3 = ${server.h3}")
                if (server.h4.isNotEmpty() && server.h4 != "0") appendLine("H4 = ${server.h4}")
            }

            // Preserve the same scope when AdBlock was explicitly disabled by the user.
            // Never fall back to a wider, global scope after a backend error.
            includedApps.forEach { appendLine("IncludedApplications = $it") }
            excludedApps.forEach { appendLine("ExcludedApplications = $it") }

            appendLine("[Peer]")
            appendLine("PublicKey = ${server.peerPublicKey}")
            if (server.peerPresharedKey.isNotEmpty()) {
                appendLine("PresharedKey = ${server.peerPresharedKey}")
            }
            appendLine("AllowedIPs = $allowedIPs")
            appendLine("Endpoint = ${server.peerEndpoint}")
            appendLine("PersistentKeepalive = ${server.peerPersistentKeepalive}")
        }
    }

    private fun publishBackendScope(allowed: List<String>, disallowed: List<String>) {
        val mode = if (allowed.isNotEmpty()) "INCLUDE" else if (disallowed.isNotEmpty()) "EXCLUDE" else "GLOBAL"
        backendAppScope = AppliedTunAppScope(mode, allowed, disallowed, true)
        AdBlockLog.add("APP_VPN_SCOPE_ACTIVE backend=" + (if (usingAwg) "AWG" else "WG") + " mode=$mode apps=" + (allowed + disallowed).joinToString(","))
    }

    private fun updateStatus(status: VpnStatus) {
        if (status != VpnStatus.CONNECTED) backendAppScope = null
        globalStatus = status
        onStatusChanged?.invoke(status)
    }

    private fun showToast(msg: String) {
        Toast.makeText(context, msg, Toast.LENGTH_LONG).show()
    }
}
