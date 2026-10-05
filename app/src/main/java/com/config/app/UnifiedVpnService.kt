package com.config.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService as AndroidVpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.system.Os
import android.system.OsConstants
import androidx.core.app.NotificationCompat
import com.wireguard.android.backend.GoBackend
import java.util.concurrent.CompletableFuture
import kotlin.concurrent.thread

// Один Android TUN. AdBlock фильтрует пакеты, затем передаёт их WG/AWG
// через packet socket и специальный tun.Device внутри Go-движка.
class UnifiedVpnService : AndroidVpnService() {

    companion object {
        const val ACTION_STOP = "com.config.vpnadblock.UNIFIED_STOP"
        const val ACTION_CONNECT = "com.config.vpnadblock.UNIFIED_CONNECT"
        private const val CHANNEL_ID = "unified_vpn"
        private const val NOTIF_ID = 1002

        @Volatile var active: Boolean = false
            private set

        // Immutable snapshot of the Builder lists from the last successful establish().
        // Never reconstructed from preferences; retained with active=false after close.
        @Volatile var tunAppScope: AppliedTunAppScope? = null
            private set

        @Volatile var tcp443DiagnosticScope: String = "OFF"
            private set

        // Результат старта привязан к request_id (ConcurrentHashMap<rid, future>).
        // Старый общий перезаписываемый readyFuture давал гонку: повторный
        // connect() заменял future, первый caller получал timeout через 30с,
        // хотя datapath реально поднялся (INLINE_ON/ACTIVE в журнале).
        private val readyFutures = java.util.concurrent.ConcurrentHashMap<Long, CompletableFuture<Boolean>>()
        private val requestIds = java.util.concurrent.atomic.AtomicLong()

        // Phase C bind: GoBackend.vpnService.complete(service).
        // false = future уже занят вложенным сервисом библиотеки.
        fun bindIntoGoBackend(service: AndroidVpnService): Boolean {
            return try {
                val f = GoBackend::class.java.getDeclaredField("vpnService")
                f.isAccessible = true
                @Suppress("UNCHECKED_CAST")
                val future = f.get(null) as CompletableFuture<AndroidVpnService>
                future.complete(service)
            } catch (e: Exception) {
                false
            }
        }

        // wg-quick текст для wg-go (зеркалит то, что собирает VpnManager для GoBackend)
        fun buildWgQuick(s: ServerInfo, awg: Boolean = false): String = buildString {
            append("[Interface]\nPrivateKey = ").append(s.interfacePrivateKey).append('\n')
            if (s.interfaceAddress.isNotEmpty()) append("Address = ").append(s.interfaceAddress).append('\n')
            if (s.interfaceDns.isNotEmpty()) append("DNS = ").append(s.interfaceDns).append('\n')
            s.interfaceMtu.toIntOrNull()?.let { if (it in 576..65535) append("MTU = ").append(it).append('\n') }
            if (awg) {
                listOf("Jc" to s.jc, "Jmin" to s.jmin, "Jmax" to s.jmax,
                    "S1" to s.s1, "S2" to s.s2, "H1" to s.h1, "H2" to s.h2,
                    "H3" to s.h3, "H4" to s.h4).forEach { (key, value) ->
                    if (value.isNotEmpty()) append(key).append(" = ").append(value).append('\n')
                }
            }
            append("[Peer]\nPublicKey = ").append(s.peerPublicKey).append('\n')
            if (s.peerPresharedKey.isNotEmpty()) append("PresharedKey = ").append(s.peerPresharedKey).append('\n')
            append("AllowedIPs = ").append(VpnManager.buildAllowedIPs(s)).append('\n')
            if (s.peerEndpoint.isNotEmpty()) append("Endpoint = ").append(s.peerEndpoint).append('\n')
            append("PersistentKeepalive = ").append(s.peerPersistentKeepalive.ifEmpty { "25" }).append('\n')
        }

        /** Phase D entry: стартует сервис с extras и ждёт результата поднятия datapath. */
        fun connectAdBlockBlocking(context: Context, server: ServerInfo, awg: Boolean = false, forceRebuild: Boolean = false): Boolean {
            val requestId = requestIds.incrementAndGet()
            val f = CompletableFuture<Boolean>()
            readyFutures[requestId] = f
            AdBlockLog.add("ADBLOCK: CONNECT_START rid=" + requestId)
            val i = Intent(context, UnifiedVpnService::class.java).setAction(ACTION_CONNECT)
                .putExtra("request_id", requestId)
                .putExtra("force_rebuild", forceRebuild)
                .putExtra("name", server.name)
                .putExtra("wgquick", buildWgQuick(server, awg))
                .putExtra("awg", awg)
                .putExtra("addresses", server.interfaceAddress)
                .putExtra("dns", server.interfaceDns)
                .putExtra("mtu", server.interfaceMtu)
                .putExtra("routes", VpnManager.buildAllowedIPs(server))
            context.startService(i)
            return try { f.get(30, java.util.concurrent.TimeUnit.SECONDS) } catch (_: Exception) {
                readyFutures.remove(requestId, f)
                f.complete(false)
                AdBlockLog.add("ADBLOCK: CONNECT_TIMEOUT rid=" + requestId)
                false
            }
        }
    }

    private var dp: Datapath? = null
    @Volatile private var stopping = false

    override fun onCreate() {
        super.onCreate()
        AdBlockLog.init(applicationContext)
        AdBlockLog.add("VPN_SERVICE_CREATE")
        bindIntoGoBackend(this)
        startForegroundWith("VPN подключается…")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        bindIntoGoBackend(this)
        when (intent?.action) {
            ACTION_STOP -> {
                stopping = true
                requestIds.incrementAndGet()
                // завершить ВСЕ ожидающие future, а не один общий
                readyFutures.forEach { (_, f) -> f.complete(false) }
                readyFutures.clear()
                stopDatapath("ACTION_STOP")
                stopSelf()
            }
            ACTION_CONNECT -> {
                val requestId = intent.getLongExtra("request_id", -1)
                val request = readyFutures[requestId]
                AdBlockLog.add("ADBLOCK: CONNECT_DISPATCH rid=" + requestId)
                thread(name = "adblock-datapath") {
                    synchronized(this) {
                        if (stopping || request == null || request.isDone) {
                            if (request != null) {
                                readyFutures.remove(requestId, request)
                                request.complete(false)
                            }
                            AdBlockLog.add("ADBLOCK: CONNECT_CANCELLED rid=$requestId")
                            return@synchronized
                        }
                        val existing = dp
                        if (!intent.getBooleanExtra("force_rebuild", false) &&
                            existing != null && existing.running && UnifiedAdBlock.running && UnifiedAdBlock.ready) {
                            // datapath уже поднят (INLINE_ON/ACTIVE) — для этого
                            // запроса честный true, а не timeout чужого future.
                            readyFutures.remove(requestId, request)
                            request?.complete(true)
                            AdBlockLog.add("ADBLOCK: CONNECT_COMPLETE rid=" + requestId + " ok=true cached")
                            return@synchronized
                        }
                        if (intent.getBooleanExtra("force_rebuild", false)) {
                            AdBlockLog.add("APP_VPN_SCOPE_REBUILD rid=$requestId")
                        }
                        val started = startDatapath(intent)
                        val ok = started && !stopping && !request.isDone
                        readyFutures.remove(requestId, request)
                        request?.complete(ok)
                        AdBlockLog.add("ADBLOCK: CONNECT_COMPLETE rid=" + requestId + " ok=" + ok)
                        if (!ok) stopDatapath("START_FAILED")
                        startForegroundWith(if (ok) "VPN подключён • фильтр запущен" else "VPN: ошибка подключения")
                    }
                }
            }
            else -> {
                startForegroundWith(if (active) "VPN подключён • фильтр запущен" else "VPN: ожидание подключения")
                if (intent == null && VpnStateStorage(this).wasConnected()) {
                    AdBlockLog.add("VPN_SERVICE_RESTORE requested")
                    // KeepAlive restores the saved server; an empty sticky restart
                    // must not pretend that a new native datapath already exists.
                    startForegroundService(Intent(this, VpnKeepAliveService::class.java))
                }
            }
        }
        return START_STICKY
    }

    override fun onDestroy() {
        stopping = true
        AdBlockLog.add("VPN_SERVICE_DESTROY")
        stopDatapath("SERVICE_DESTROY")
        try { stopForeground(true) } catch (_: Exception) {}
        super.onDestroy()
    }

    override fun onRevoke() {
        stopping = true
        AdBlockLog.add("VPN_PERMISSION_REVOKED")
        VpnStateStorage(this).setWasConnected(false)
        stopDatapath("VPN_REVOKED")
        stopSelf()
    }

    // ---------------- Phase D datapath ----------------

    private inner class Datapath {
        var tunPfd: ParcelFileDescriptor? = null
        lateinit var appFd: java.io.FileDescriptor
        lateinit var wgLocal: java.io.FileDescriptor
        var packetEngine = false
        @Volatile var running = false
        @Volatile var rxBytes = 0L
        @Volatile var inlineEngine = false
    }

    @Synchronized
    private fun startDatapath(intent: Intent): Boolean {
        stopDatapath("REPLACE_DATAPATH")
        return try {
            DnsFilter.load(applicationContext)
            val name = (intent.getStringExtra("name") ?: "cvab").take(24)
            val wgquick = intent.getStringExtra("wgquick") ?: return failDp("no wgquick")
            val awg = intent.getBooleanExtra("awg", false)
            val addresses = intent.getStringExtra("addresses") ?: ""
            val dns = intent.getStringExtra("dns") ?: ""
            val routes = intent.getStringExtra("routes") ?: "0.0.0.0/0, ::/0"
            val mtu = intent.getStringExtra("mtu")?.toIntOrNull()?.takeIf { it in 576..65535 } ?: 1280

            // Resolve endpoints before establishing the Android VPN interface.
            val settings = if (awg) {
                org.amnezia.awg.config.Config.parse(java.io.ByteArrayInputStream(wgquick.toByteArray()))
                    .toAwgUserspaceString(false, this)
            } else {
                com.wireguard.config.Config.parse(java.io.ByteArrayInputStream(wgquick.toByteArray()))
                    .toWgUserspaceString()
            }

            // интерфейс для приложений — единственный видимый Android'ом
            val b = Builder()
            b.setSession(name)
            b.setMtu(mtu)
            b.setBlocking(true)
            val appConfig = AppVpnStorage(this).configuration()
            val scopeMode = if (appConfig.enabled && appConfig.packages.isNotEmpty()) appConfig.mode else "GLOBAL"
            val allowed = if (scopeMode == "INCLUDE") appConfig.packages else emptyList()
            val disallowed = if (scopeMode == "EXCLUDE") appConfig.packages else emptyList()
            allowed.forEach { b.addAllowedApplication(it) }
            disallowed.forEach { b.addDisallowedApplication(it) }
            val scopeDetail = "mode=$scopeMode" + if (scopeMode == "GLOBAL") ""
                else " apps=" + (allowed + disallowed).joinToString(",")
            addresses.split(",").map { it.trim() }.filter { it.isNotEmpty() }.forEach { a ->
                val ip: String; val pl: Int
                if ("/" in a) {
                    ip = a.substringBefore("/").trim()
                    pl = a.substringAfter("/").trim().toIntOrNull() ?: (if (":" in ip) 128 else 32)
                } else {
                    ip = a; pl = if (":" in ip) 128 else 32
                }
                b.addAddress(ip, pl)
            }
            dns.split(",").map { it.trim() }.filter { it.isNotEmpty() }.forEach { b.addDnsServer(it) }
            routes.split(",").map { it.trim() }.filter { it.isNotEmpty() }.forEach { r ->
                val ip: String; val pl: Int
                if ("/" in r) {
                    ip = r.substringBefore("/").trim()
                    pl = r.substringAfter("/").trim().toIntOrNull() ?: (if (":" in ip) 128 else 32)
                } else {
                    ip = r; pl = if (":" in ip) 128 else 32
                }
                b.addRoute(ip, pl)
            }
            AdBlockLog.add("APP_VPN_SCOPE_APPLY $scopeDetail")
            val tun = b.establish() ?: return failDp("tun establish failed")

            val d = Datapath()
            d.tunPfd = tun
            d.appFd = tun.fileDescriptor
            dp = d
            tunAppScope = AppliedTunAppScope(scopeMode, allowed.toList(), disallowed.toList(), true)
            AdBlockLog.add("APP_VPN_SCOPE_ACTIVE $scopeDetail")
            val fdA = java.io.FileDescriptor()
            val fdB = java.io.FileDescriptor()
            Os.socketpair(OsConstants.AF_UNIX, OsConstants.SOCK_SEQPACKET, 0, fdA, fdB)
            d.wgLocal = fdA
            val nativeFd = try { ParcelFileDescriptor.dup(fdB).detachFd() }
                finally { Os.close(fdB) }

            if (!UnifiedAdBlock.start(this)) {
                ParcelFileDescriptor.adoptFd(nativeFd).close()
                return failDp("AdBlock engine initialization failed")
            }
            configureTCP443Diagnostic(scopeMode, allowed)
            // StartPacketVPN takes ownership of nativeFd, even on error.
            mitm.Mitm.startPacketVPN(nativeFd.toLong(), mtu.toLong(), settings)
            d.packetEngine = true
            d.running = true
            AdBlockLog.add("UNIFIED_NATIVE_UP mode=" + if (awg) "AWG" else "WG")
            val wgAddr = addresses.split(",").firstOrNull { it.trim().isNotEmpty() }
                ?.trim()?.substringBefore("/") ?: return failDp("VPN address missing")
            // Pass one owned descriptor at a time; native startup closes it on failure.
            val wgDns = Regex("(?im)^\\s*DNS\\s*=\\s*([0-9A-Fa-f.:]+)").find(wgquick)?.groupValues?.get(1) ?: ""
            mitm.Mitm.setWgUpstream(ParcelFileDescriptor.dup(d.wgLocal).detachFd().toLong(), mtu.toLong(), wgAddr, wgDns)
            mitm.Mitm.startTunnel(ParcelFileDescriptor.dup(d.appFd).detachFd().toLong(), mtu.toLong())
            d.inlineEngine = true
            active = true
            AdBlockLog.add("UNIFIED_ADBLOCK_INLINE_ON addr=$wgAddr mtu=$mtu")
            AdBlockLog.add("ADBLOCK: ACTIVE mtu=$mtu routes=" + routes.take(60))
            true
        } catch (e: Throwable) {
            AdBlockLog.add("ADBLOCK: ERROR " + (e.message ?: e.javaClass.simpleName))
            stopDatapath("START_EXCEPTION")
            false
        }
    }

    // alpha77 experiment uses the Builder scope that successfully established
    // this TUN; Android already restricts which applications can enter it.
    private fun configureTCP443Diagnostic(mode: String, allowed: List<String>) {
        mitm.Mitm.setDirect443(false)
        mitm.Mitm.setDirect443Scope(null)
        mitm.Mitm.resetTCP443Diagnostics()
        val includeScope = mode == "INCLUDE" && allowed.isNotEmpty()
        mitm.Mitm.setTcp443RawInclude(false)
        mitm.Mitm.setQuicIncludeDiagnostic(mode, allowed.joinToString(","))
        tcp443DiagnosticScope = if (includeScope) "NORMAL_TCP_QUIC_DROP_DIAG" else "OFF"
        AdBlockLog.add("TCP443_MODE mode=" + (if (includeScope) "NORMAL_TCP_QUIC_DROP_DIAG" else "NORMAL") +
            " tunAppScope=$mode DNS_SNI_BLOCK_ON WG_ONLY")
    }

    private fun failDp(why: String): Boolean {
        AdBlockLog.add("ADBLOCK: ERROR $why")
        stopDatapath("START_FAILED: $why")
        return false
    }

    @Synchronized
    private fun stopDatapath(reason: String) {
        // An idle/old service must not stop the process-wide engine owned by
        // a different service instance.
        val d = dp ?: return
        active = false
        runCatching { mitm.Mitm.stopQuicIncludeDiagnostic(); mitm.Mitm.setTcp443RawInclude(false); mitm.Mitm.setDirect443(false); mitm.Mitm.setDirect443Scope(null) }
        tcp443DiagnosticScope = "OFF"
        AdBlockLog.add("DATAPATH_STOP reason=$reason")
        runCatching {
            AdBlockLog.add("LAST_VPN " + mitm.Mitm.packetVPNStats())
            AdBlockLog.add("LAST_UPSTREAM " + mitm.Mitm.wgUpstreamStats())
            AdBlockLog.add("LAST_TUN " + mitm.Mitm.tunStats())
            AdBlockLog.add("LAST_MITM " + mitm.Mitm.mitmStats())
            AdBlockLog.add("LAST_FLOW " + mitm.Mitm.flowLog())
        }
        runCatching { UnifiedAdBlock.stop() }
        if (reason != "REPLACE_DATAPATH") {
            android.os.Handler(mainLooper).post {
                if (!active) VpnManager.getInstance(applicationContext).onUnifiedStopped(reason)
            }
        }
        if (d.packetEngine) {
            runCatching { mitm.Mitm.stopTunnel() }
            runCatching { mitm.Mitm.clearWgUpstream() }
        }
        dp = null
        d.running = false
        if (d.packetEngine) runCatching { mitm.Mitm.stopPacketVPN() }
        d.packetEngine = false
        runCatching { Os.close(d.wgLocal) }
        runCatching { d.tunPfd?.close() }
        d.tunPfd = null
        tunAppScope = tunAppScope?.copy(active = false)
    }

    fun currentRx(): Long = dp?.rxBytes ?: 0L

    // ---------------- notification ----------------

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


data class AppliedTunAppScope(val mode: String, val allowedApps: List<String>,
    val disallowedApps: List<String>, val active: Boolean)
