package com.config.app

import android.content.Context
import android.net.VpnService
import android.util.Log
import java.io.File

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


    private fun marker(line: String) {
        AdBlockLog.add(line)
        Log.i("UnifiedAdBlock", line)
    }

    @Synchronized
    fun start(vpn: UnifiedVpnService): Boolean {
        if (running) return ready
        running = true
        ready = false
        marker("UNIFIED_ADBLOCK_SOURCE " + SOURCE)
        marker("UNIFIED_ADBLOCK_START")
        return try {
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
                mitm.Mitm.setProtector(object : mitm.Protector {
                        override fun protect(fd: Long): Boolean = try {
                            vpn.protect(fd.toInt())
                        } catch (_: Exception) {
                            false
                        }
                    })
                mitm.Mitm.startProxy(filesDir.absolutePath, blFile.absolutePath)
                mitm.Mitm.setContentFilter(true)

                ready = true
                marker("UNIFIED_ADBLOCK_READY")
                true
            } catch (t: Throwable) {
                ready = false
                running = false
                runCatching { mitm.Mitm.stopProxy() }
                marker("UNIFIED_ADBLOCK_ERROR " + (t.message ?: t.javaClass.simpleName))
                false
            }
    }

    @Synchronized
    fun stop() {
        if (!running) return
        running = false
        ready = false
        runCatching { mitm.Mitm.stopProxy() }
        marker("UNIFIED_ADBLOCK_STOP")
    }
}
