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
import android.system.StructPollfd
import androidx.core.app.NotificationCompat
import com.wireguard.android.backend.GoBackend
import java.util.concurrent.CompletableFuture
import kotlin.concurrent.thread
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull

// Phase C+D: единый VPN slot для всего приложения.
//
// Phase C (AdBlock OFF): рефлексивный bind в GoBackend.vpnService — wg-go строит
// TUN через наш Builder, всё как раньше.
//
// Phase D (AdBlock ON): приложения видят ТОЛЬКО наш интерфейс (Builder +
// establish в этом сервисе). Между приложениями и wg-go — socketpair
// (SOCK_SEQPACKET = пакетные границы). Форвардер гоняет пакеты туда-обратно и
// пропускает DNS-запросы через DnsFilter (NXDOMAIN для рекламных доменов).
// wg-go получает fd сокетпейра через приватный native wgTurnOn (WgGoReflex).
// Один VpnService, один интерфейс, одна notification — второго VPN slot нет.
class UnifiedVpnService : AndroidVpnService() {

    companion object {
        const val ACTION_STOP = "com.config.vpnadblock.UNIFIED_STOP"
        const val ACTION_CONNECT = "com.config.vpnadblock.UNIFIED_CONNECT"
        private const val CHANNEL_ID = "unified_vpn"
        private const val NOTIF_ID = 1001

        @Volatile
        private var readyFuture: CompletableFuture<Boolean>? = null

        @Synchronized
        private fun resetReady(): CompletableFuture<Boolean> {
            val f = CompletableFuture<Boolean>()
            readyFuture = f
            return f
        }

        private fun notifyReady(ok: Boolean) {
            readyFuture?.complete(ok)
        }

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
        fun connectAdBlockBlocking(context: Context, server: ServerInfo, awg: Boolean = false): Boolean {
            val f = resetReady()
            val i = Intent(context, UnifiedVpnService::class.java).setAction(ACTION_CONNECT)
                .putExtra("name", server.name)
                .putExtra("wgquick", buildWgQuick(server, awg))
                .putExtra("awg", awg)
                .putExtra("addresses", server.interfaceAddress)
                .putExtra("dns", server.interfaceDns)
                .putExtra("mtu", server.interfaceMtu)
                .putExtra("routes", VpnManager.buildAllowedIPs(server))
            context.startService(i)
            return runBlocking { withTimeoutOrNull(15000) { f.get() } } == true
        }
    }

    private var dp: Datapath? = null

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
                stopDatapath()
                stopSelf()
            }
            ACTION_CONNECT -> thread(name = "adblock-datapath") {
                val ok = startDatapath(intent)
                notifyReady(ok)
                if (ok) startForegroundWith(if (dp?.inlineEngine == true) "VPN активен • AdBlock работает" else "VPN активен • HTTPS-фильтр недоступен")
                else startForegroundWith("VPN: ошибка подключения")
            }
            else -> startForegroundWith("VPN активен • AdBlock: не подключён")
        }
        return START_STICKY
    }

    override fun onDestroy() {
        stopDatapath()
        try { stopForeground(true) } catch (_: Exception) {}
        super.onDestroy()
    }

    // ---------------- Phase D datapath ----------------

    private inner class Datapath {
        var tunPfd: ParcelFileDescriptor? = null
        lateinit var appFd: java.io.FileDescriptor
        lateinit var wgLocal: java.io.FileDescriptor
        var handle: Int = -1
        var awg = false
        @Volatile var running = false
        @Volatile var rxBytes = 0L
        @Volatile var inlineEngine = false
    }

    private fun startDatapath(intent: Intent): Boolean {
        return try {
            DnsFilter.load(applicationContext)
            val name = (intent.getStringExtra("name") ?: "cvab").take(24)
            val wgquick = intent.getStringExtra("wgquick") ?: return failDp("no wgquick")
            val awg = intent.getBooleanExtra("awg", false)
            val addresses = intent.getStringExtra("addresses") ?: ""
            val dns = intent.getStringExtra("dns") ?: ""
            val routes = intent.getStringExtra("routes") ?: "0.0.0.0/0, ::/0"
            val mtu = intent.getStringExtra("mtu")?.toIntOrNull()?.takeIf { it in 576..65535 } ?: 1280

            // socketpair: wg-go получит один конец как «tun», мы держим другой.
            // SDK 36: двухаргументной сигнатуры нет — используем вариант с out-fd.
            val fdA = java.io.FileDescriptor()
            val fdB = java.io.FileDescriptor()
            Os.socketpair(OsConstants.AF_UNIX, OsConstants.SOCK_SEQPACKET, 0, fdA, fdB)
            val pair = arrayOf(fdA, fdB)
            val wgFdInt = ParcelFileDescriptor.dup(pair[1]).detachFd()

            // интерфейс для приложений — единственный видимый Android'ом
            val b = Builder()
            b.setSession(name)
            b.setMtu(mtu)
            b.setBlocking(true)
            val appPrefs = AppVpnStorage(this)
            if (appPrefs.isEnabled()) {
                val included = appPrefs.getSelectedPackages()
                val excluded = appPrefs.getExcludedPackages()
                if (included.isNotEmpty()) included.forEach { b.addAllowedApplication(it) }
                else excluded.forEach { b.addDisallowedApplication(it) }
            }
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
            val tun = b.establish() ?: return failDp("tun establish failed")

            val d = Datapath()
            d.awg = awg
            d.tunPfd = tun
            d.appFd = tun.fileDescriptor
            d.wgLocal = pair[0]
            dp = d

            // The native WG API expects userspace key=value lines; the AWG 2.3.7
            // backend expects its resolved quick format and a UAPI directory.
            val handle = if (awg) {
                val cfg = org.amnezia.awg.config.Config.parse(java.io.ByteArrayInputStream(wgquick.toByteArray()))
                org.amnezia.awg.GoBackend.awgTurnOn(name.take(15), wgFdInt,
                    cfg.toAwgQuickStringResolved(false, false, false, this), dataDir.absolutePath)
            } else {
                val cfg = com.wireguard.config.Config.parse(java.io.ByteArrayInputStream(wgquick.toByteArray()))
                WgGoReflex.turnOn(name.take(15), wgFdInt, cfg.toWgUserspaceString())
            }
            if (handle < 0) return failDp("native tunnel returned $handle awg=$awg")
            d.handle = handle
            d.running = true
            runCatching { val s = if (awg) org.amnezia.awg.GoBackend.awgGetSocketV4(handle) else WgGoReflex.socketV4(handle); if (s >= 0) protect(s) }
            runCatching { val s = if (awg) org.amnezia.awg.GoBackend.awgGetSocketV6(handle) else WgGoReflex.socketV6(handle); if (s >= 0) protect(s) }
            AdBlockLog.add("UNIFIED_NATIVE_UP mode=" + if (awg) "AWG" else "WG")
            // Сначала запускаем proxy/CA/blocklist, затем подключаем стек и TUN.
            // Иначе первые пакеты проходят через движок без готового фильтра.
            val adbOn = getSharedPreferences("app_prefs", MODE_PRIVATE).getBoolean("adblock_enabled", false)
            AdBlockLog.add("ADBLOCK_PREF enabled=" + adbOn)
            if (!adbOn) AdBlockLog.add("UNIFIED_ADBLOCK_DISABLED pref=false")
            val engineReady = adbOn && UnifiedAdBlock.start(this)
            val wgAddr = Regex("(?im)^\\s*Address\\s*=\\s*([0-9A-Fa-f.:]+)").find(wgquick)?.groupValues?.get(1) ?: ""
            var inlineOk = false
            if (engineReady && wgAddr.isNotEmpty()) {
                val appFdInt = runCatching { ParcelFileDescriptor.dup(d.appFd).detachFd() }.getOrDefault(-1)
                val wgFdInt2 = runCatching { ParcelFileDescriptor.dup(d.wgLocal).detachFd() }.getOrDefault(-1)
                inlineOk = appFdInt >= 0 && wgFdInt2 >= 0 && runCatching {
                    mitm.Mitm.setWgUpstream(wgFdInt2.toLong(), mtu.toLong(), wgAddr)
                    mitm.Mitm.startTunnel(appFdInt.toLong(), mtu.toLong())
                    true
                }.onFailure { AdBlockLog.add("UNIFIED_ADBLOCK_ERROR tunnel: ${it.message}") }.getOrDefault(false)
            }
            if (inlineOk) {
                d.inlineEngine = true
                AdBlockLog.add("UNIFIED_ADBLOCK_INLINE_ON addr=$wgAddr mtu=$mtu")
            } else {
                if (engineReady) UnifiedAdBlock.stop()
                runCatching { mitm.Mitm.clearWgUpstream() }
                AdBlockLog.add("UNIFIED_ADBLOCK_INLINE_FALLBACK packet-forwarder (HTTPS filter unavailable)")
                startForwarder(d)
            }
            AdBlockLog.add("ADBLOCK: ACTIVE mtu=$mtu routes=" + routes.take(60))
            true
        } catch (e: Throwable) {
            AdBlockLog.add("ADBLOCK: ERROR " + (e.message ?: e.javaClass.simpleName))
            stopDatapath()
            false
        }
    }

    private fun failDp(why: String): Boolean {
        AdBlockLog.add("ADBLOCK: ERROR $why")
        stopDatapath()
        return false
    }

    private fun startForwarder(d: Datapath) {
        thread(name = "cvab-fwd", isDaemon = true) {
            val buf = ByteArray(65535)
            val pollIn = 1.toShort() // POLLIN
            val appFd = d.appFd
            val wgFd = d.wgLocal
            val pApp = StructPollfd().apply { fd = appFd; events = pollIn }
            val pWg = StructPollfd().apply { fd = wgFd; events = pollIn }
            val pfds = arrayOf(pApp, pWg)
            while (d.running) {
                try {
                    pApp.revents = 0; pWg.revents = 0
                    Os.poll(pfds, 1000)
                    if (pApp.revents.toInt() and 1 != 0) {
                        val n = Os.read(d.appFd, buf, 0, buf.size)
                        if (n <= 0) break
                        d.rxBytes += n
                        val blocked = if (getSharedPreferences("app_prefs", MODE_PRIVATE).getBoolean("adblock_enabled", false))
                            runCatching { DnsFilter.tryBlock(buf, n) }.getOrNull() else null
                        if (blocked != null) {
                            Os.write(d.appFd, blocked, 0, blocked.size)
                        } else {
                            Os.write(d.wgLocal, buf, 0, n)
                        }
                    }
                    if (pWg.revents.toInt() and 1 != 0) {
                        val n = Os.read(d.wgLocal, buf, 0, buf.size)
                        if (n <= 0) break
                        Os.write(d.appFd, buf, 0, n)
                    }
                } catch (e: Exception) {
                    if (d.running) {
                        AdBlockLog.add("ADBLOCK: ERROR fwd " + (e.message ?: e.javaClass.simpleName))
                    }
                    break
                }
            }
            d.running = false
            AdBlockLog.add("ADBLOCK: forwarder exit")
        }
    }

    private fun stopDatapath() {
        runCatching { UnifiedAdBlock.stop() }
        val d = dp ?: return
        if (d.inlineEngine) {
            runCatching { mitm.Mitm.stopTunnel() }
            runCatching { mitm.Mitm.clearWgUpstream() }
        }
        dp = null
        d.running = false
        runCatching {
            if (d.handle >= 0) {
                if (d.awg) org.amnezia.awg.GoBackend.awgTurnOff(d.handle)
                else WgGoReflex.turnOff(d.handle)
            }
        }
        d.handle = -1
        runCatching { Os.close(d.wgLocal) }
        runCatching { d.tunPfd?.close() }
        d.tunPfd = null
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
