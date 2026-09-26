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

    // WireGuard: серверы БЕЗ junk-параметров — здесь App VPN (IncludedApplications)
    // работает гарантированно (проверено).
    private val wgBackend: WgBackend = WgGoBackend(context.applicationContext)

    // AmneziaWG: серверы С junk-параметрами Jc/Jmin/Jmax/S1/S2/H1-H4 —
    // маскируют WireGuard от DPI РНК. App VPN для таких серверов не гарантируется.
    private val awgBackend: AwgBackend = AwgGoBackend(context.applicationContext, NoopTunnelActionHandler())

    private var currentWgConfig: WgConfig? = null
    private var currentAwgConfig: AwgConfig? = null
    private var usingAwg = false
    private val vpnStateStorage = VpnStateStorage(context)

    var onStatusChanged: ((VpnStatus) -> Unit)? = null
    var onServerChanged: ((ServerInfo?) -> Unit)? = null

    private var currentServer: ServerInfo? = null
    private val scope = CoroutineScope(Dispatchers.IO)

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
        scope.launch {
            try {
                val prepareIntent = VpnService.prepare(context)
                if (prepareIntent != null) {
                    withContext(Dispatchers.Main) {
                        updateStatus(VpnStatus.ERROR)
                        showToast("Ошибка: разрешение VPN не дано. Откройте приложение и нажмите CONNECT.")
                    }
                    return@launch
                }

                currentServer = server
                withContext(Dispatchers.Main) {
                    onServerChanged?.invoke(server)
                    updateStatus(VpnStatus.CONNECTING)
                }

                vpnStateStorage.setWasConnected(true)
                vpnStateStorage.setLastServer(server.id)

                val serviceIntent = Intent(context, VpnKeepAliveService::class.java)
                if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                    context.startForegroundService(serviceIntent)
                } else {
                    context.startService(serviceIntent)
                }

                val includedApps = AppVpnStorage(context).getSelectedPackages().toList()

                // Конфиг с junk-параметрами (AmneziaWG) идёт через AWG-бэкенд —
                // он обходит DPI РНК. Обычные конфиги — через WireGuard с App VPN.
                val wantsAwg = server.jc.isNotEmpty() && server.jc != "0"
                if (wantsAwg) {
                    connectAwg(server, includedApps)
                } else {
                    connectWg(server, includedApps)
                }

                withContext(Dispatchers.Main) {
                    updateStatus(VpnStatus.CONNECTED)
                    StopVpnWidget.updateWidget(context, VpnStatus.CONNECTED)
                }
            } catch (e: Exception) {
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
    }

    private suspend fun connectWg(server: ServerInfo, includedApps: List<String>) {
        val configString = buildConfigString(server, includedApps, withAwg = false)

        val config = WgConfig.parse(ByteArrayInputStream(configString.toByteArray()))
        currentWgConfig = config
        usingAwg = false

        val tunnel = WgTunnel.getInstance()
        // Phase C: единый VPN slot — наш foreground-сервис биндится в GoBackend
        // до setState, TUN строится через его Builder (single interface).
        context.startForegroundService(Intent(context, UnifiedVpnService::class.java))
        // Phase D: AdBlock ON → свой datapath (TUN ↔ форвардер+DNS-фильтр ↔ wg-go
        // через socketpair). Не поднялся — fail-open в обычный WG-путь ниже.
        if (context.getSharedPreferences("app_prefs", Context.MODE_PRIVATE).getBoolean("adblock_enabled", false)) {
            val adOk = UnifiedVpnService.connectAdBlockBlocking(context, server)
            if (adOk) {
                dbg("ADBLOCK: ACTIVE")
                probePaths()
                return
            }
            dbg("ADBLOCK: datapath failed, fail-open to plain WG")
            AdBlockLog.add("ADBLOCK: ERROR datapath failed, fail-open to plain WG")
        }
        try {
            val t0 = System.currentTimeMillis()
            wgBackend.setState(tunnel, WgBackendTunnel.State.UP, config)
            android.util.Log.d("ConfigVPN", "WG handshake: ${System.currentTimeMillis() - t0} ms")
            dbg("WG up: " + (System.currentTimeMillis() - t0) + " ms")
        } catch (e: Exception) {
            if (includedApps.isNotEmpty()) {
                android.util.Log.w("ConfigVPN", "Backend failed with IncludedApplications, retrying without...", e)
                val fallbackConfig = WgConfig.parse(ByteArrayInputStream(buildConfigString(server).toByteArray()))
                wgBackend.setState(tunnel, WgBackendTunnel.State.UP, fallbackConfig)
                withContext(Dispatchers.Main) {
                    showToast("App VPN: приложение не найдено, VPN работает для всех")
                }
            } else {
                throw e
            }
        }

        warnIfNoTraffic {
            runCatching { wgBackend.getStatistics(tunnel).totalRx() }.getOrNull()
        }
        probePaths()
    }

    private suspend fun connectAwg(server: ServerInfo, includedApps: List<String>) {
        try {
            val configString = buildConfigString(server, includedApps, withAwg = true)

            val config = AwgConfig.parse(ByteArrayInputStream(configString.toByteArray()))
            currentAwgConfig = config
            usingAwg = true

            val t0 = System.currentTimeMillis()
            awgBackend.setState(AwgTunnel.getInstance(), AwgBackendTunnel.State.UP, config)
            android.util.Log.d("ConfigVPN", "AWG handshake: ${System.currentTimeMillis() - t0} ms")

            warnIfNoTraffic {
                runCatching { awgBackend.getStatistics(AwgTunnel.getInstance()).totalRx() }.getOrNull()
            }
            probePaths()
        } catch (e: Exception) {
            // Фолбэк: сервер не принял junk-параметры — пробуем обычный WireGuard
            android.util.Log.w("ConfigVPN", "AWG failed, falling back to plain WireGuard", e)
            dbg("AWG FAILED: " + (e.stackTraceToString() ?: e.toString()).take(1500))
            connectWg(server, includedApps)
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
        scope.launch {
            try {
                withContext(Dispatchers.Main) {
                    updateStatus(VpnStatus.DISCONNECTING)
                }

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

        @Volatile
        private var instance: VpnManager? = null

        fun getInstance(context: Context): VpnManager {
            return instance ?: synchronized(this) {
                instance ?: VpnManager(context).also { instance = it }
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

    private fun buildConfigString(server: ServerInfo, includedApps: List<String> = emptyList(), withAwg: Boolean = false): String {
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

            // App VPN: парсеры ОБЕИХ библиотек (WireGuard и AmneziaWG 2.3.7)
            // поддерживают IncludedApplications — байткод GoBackend подтверждает.
            val pm = context.packageManager
            val validApps = includedApps.filter { pkg ->
                try { pm.getApplicationInfo(pkg, 0); true }
                catch (e: Exception) { android.util.Log.w("ConfigVPN", "App не установлено: $pkg"); false }
            }
            validApps.forEach { appendLine("IncludedApplications = $it") }

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

    private fun updateStatus(status: VpnStatus) {
        globalStatus = status
        onStatusChanged?.invoke(status)
    }

    private fun showToast(msg: String) {
        Toast.makeText(context, msg, Toast.LENGTH_LONG).show()
    }
}
