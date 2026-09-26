package com.config.app

import android.content.Context
import android.net.VpnService
import android.util.Log
import java.io.File
import kotlin.concurrent.thread

/**
 * AdBlock engine wrapper — проект №4.
 * Движок перенесён из ConfigAdBlock beta7 (commit 37c49e4c, versionCode 250).
 * Запускается ВНУТРИ процесса UnifiedVpnService: один VpnService,
 * второй VPN-интерфейс не создаётся. DNS-фильтрация datapath'а (DnsFilter)
 * не трогается — движок инициализирует CA/MITM/DNS-SNI ядро и прокси.
 *
 * Маркеры журнала:
 *   UNIFIED_ADBLOCK_SOURCE beta7-37c49e4c
 *   UNIFIED_ADBLOCK_START / UNIFIED_ADBLOCK_READY
 *   UNIFIED_ADBLOCK_STOP / UNIFIED_ADBLOCK_ERROR <reason>
 */
object UnifiedAdBlock {
    const val SOURCE = "beta7-37c49e4c"

    @Volatile
    var running: Boolean = false
        private set

    @Volatile
    var ready: Boolean = false
        private set

    private var engineThread: Thread? = null

    private fun marker(line: String) {
        AdBlockLog.add(line)
        Log.i("UnifiedAdBlock", line)
    }

    fun start(vpn: UnifiedVpnService) {
        if (running) return
        running = true
        ready = false
        marker("UNIFIED_ADBLOCK_SOURCE " + SOURCE)
        marker("UNIFIED_ADBLOCK_START")
        engineThread = thread(name = "unified-adblock-engine") {
            try {
                val filesDir = vpn.filesDir
                // CA и assetDir в filesDir (как beta7): cacheDir система может стереть,
                // тогда CA перегенерируется и установленный сертификат перестанет совпадать.
                val assetDir = vpn.filesDir

                // blocklist из assets -> files (движок читает по пути)
                val blFile = File(filesDir, "blocklist.txt")
                vpn.assets.open("blocklist.txt").use { input ->
                    blFile.outputStream().use { output -> input.copyTo(output) }
                }
                // cosmetic rules -> assetDir (SetAssetDir)
                runCatching {
                    vpn.assets.open("generic_cosmetic_rules.txt").use { input ->
                        File(assetDir, "generic_cosmetic_rules.txt").outputStream().use { output -> input.copyTo(output) }
                    }
                }

                // CA init + MITM/DNS-SNI engine (создаёт ca.crt/ca.key в assetDir)
                mitm.Mitm.setAssetDir(assetDir.absolutePath)
                runCatching {
                    mitm.Mitm.setProtector(object : mitm.Protector {
                        override fun protect(fd: Long): Boolean = try {
                            vpn.protect(fd.toInt())
                        } catch (_: Exception) {
                            false
                        }
                    })
                }
                mitm.Mitm.startProxy(filesDir.absolutePath, blFile.absolutePath)
                // HTTPS-фильтрация (MITM/SNI/AD_PAYLOAD_BLOCK) — без этого DNS-only.
                runCatching { mitm.Mitm.setContentFilter(true) }

                ready = true
                marker("UNIFIED_ADBLOCK_READY")
            } catch (t: Throwable) {
                ready = false
                marker("UNIFIED_ADBLOCK_ERROR " + (t.message ?: t.javaClass.simpleName))
            }
        }
    }

    // Запуск движка из UI (без VPN): без protect (VPN не активен), contentFilter включаем.
    fun startFromUi(ctx: android.content.Context) {
        if (running) return
        running = true
        ready = false
        marker("UNIFIED_ADBLOCK_SOURCE " + SOURCE)
        marker("UNIFIED_ADBLOCK_START")
        engineThread = thread(name = "unified-adblock-engine") {
            try {
                val filesDir = ctx.filesDir
                val assetDir = ctx.filesDir
                val blFile = java.io.File(filesDir, "blocklist.txt")
                ctx.assets.open("blocklist.txt").use { input ->
                    blFile.outputStream().use { output -> input.copyTo(output) }
                }
                runCatching {
                    ctx.assets.open("generic_cosmetic_rules.txt").use { input ->
                        java.io.File(assetDir, "generic_cosmetic_rules.txt").outputStream().use { output -> input.copyTo(output) }
                    }
                }
                mitm.Mitm.setAssetDir(assetDir.absolutePath)
                mitm.Mitm.startProxy(filesDir.absolutePath, blFile.absolutePath)
                runCatching { mitm.Mitm.setContentFilter(true) }
                ready = true
                marker("UNIFIED_ADBLOCK_READY")
            } catch (t: Throwable) {
                ready = false
                marker("UNIFIED_ADBLOCK_ERROR " + (t.message ?: t.javaClass.simpleName))
            }
        }
    }

    fun stop() {
        if (!running) return
        running = false
        ready = false
        runCatching { mitm.Mitm.stopProxy() }
        marker("UNIFIED_ADBLOCK_STOP")
    }
}
