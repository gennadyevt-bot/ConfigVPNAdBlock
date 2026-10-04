package com.config.app

import android.content.Context
import android.content.SharedPreferences

class AppVpnStorage(context: Context) {

    private val prefs: SharedPreferences = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    // Publish the entire scope together, before a running VPN rebuild reads it.
    fun saveConfiguration(packages: Set<String>, includeMode: Boolean, serverId: String) {
        prefs.edit()
            .putStringSet(SELECTED_KEY, if (includeMode) HashSet(packages) else emptySet())
            .putStringSet(EXCLUDED_KEY, if (includeMode) emptySet() else HashSet(packages))
            .putBoolean(ENABLED_KEY, packages.isNotEmpty())
            .putString(MODE_KEY, if (includeMode) "INCLUDE" else "EXCLUDE")
            .putString(SERVER_ID_KEY, serverId)
            .apply()
    }

    // One preferences snapshot keeps mode, lists and enablement consistent.
    fun configuration(): AppVpnConfiguration {
        val all = prefs.all
        val included = (all[SELECTED_KEY] as? Set<*>)?.filterIsInstance<String>()?.sorted().orEmpty()
        val excluded = (all[EXCLUDED_KEY] as? Set<*>)?.filterIsInstance<String>()?.sorted().orEmpty()
        val mode = if (included.isNotEmpty()) "INCLUDE" else if (excluded.isNotEmpty()) "EXCLUDE"
            else if (all[MODE_KEY] == "EXCLUDE") "EXCLUDE" else "INCLUDE"
        return AppVpnConfiguration(all[ENABLED_KEY] == true, mode,
            if (mode == "INCLUDE") included else excluded, all[SERVER_ID_KEY] as? String ?: "")
    }

    fun setSelectedPackages(packages: Set<String>) {
        // HashSet() — обязательно, иначе putStringSet не видит изменения того же Set
        prefs.edit().putStringSet(SELECTED_KEY, HashSet(packages)).apply()
    }

    fun getSelectedPackages(): Set<String> {
        return HashSet(prefs.getStringSet(SELECTED_KEY, emptySet()) ?: emptySet())
    }

    fun setExcludedPackages(packages: Set<String>) {
        prefs.edit().putStringSet(EXCLUDED_KEY, HashSet(packages)).apply()
    }

    fun getExcludedPackages(): Set<String> {
        return HashSet(prefs.getStringSet(EXCLUDED_KEY, emptySet()) ?: emptySet())
    }

    fun setServerId(serverId: String) {
        prefs.edit().putString(SERVER_ID_KEY, serverId).apply()
    }

    fun getServerId(): String {
        return prefs.getString(SERVER_ID_KEY, "") ?: ""
    }

    fun setEnabled(enabled: Boolean) {
        prefs.edit().putBoolean(ENABLED_KEY, enabled).apply()
    }

    fun isEnabled(): Boolean {
        return prefs.getBoolean(ENABLED_KEY, false)
    }

    companion object {
        private const val PREFS_NAME = "app_vpn_prefs"
        private const val SELECTED_KEY = "selected_packages"
        private const val EXCLUDED_KEY = "excluded_packages"
        private const val MODE_KEY = "app_vpn_mode"
        private const val ENABLED_KEY = "app_vpn_enabled"
        private const val SERVER_ID_KEY = "app_vpn_server_id"
    }
}

data class AppVpnConfiguration(val enabled: Boolean, val mode: String,
    val packages: List<String>, val serverId: String)

// Displays applied scope when a unified TUN exists, rather than claiming that
// saved settings are already active during a rebuild or a disconnected VPN.
fun appVpnStatusText(config: AppVpnConfiguration): String {
    val applied = UnifiedVpnService.tunAppScope
    val connected = VpnManager.globalStatus == VpnStatus.CONNECTED
    if (connected && applied?.active == true) {
        if (applied.mode != "GLOBAL") {
            val apps = if (applied.mode == "INCLUDE") applied.allowedApps else applied.disallowedApps
            val suffix = if (applied.mode == "EXCLUDE") " • обход VPN" else ""
            return "App VPN: ВКЛ • ${appVpnCountText(apps.size)}$suffix"
        }
        return if (config.enabled) "App VPN: настроен • TUN пока GLOBAL" else "App VPN: ВЫКЛ"
    }
    if (!config.enabled) return "App VPN: ВЫКЛ"
    return when (VpnManager.globalStatus) {
        VpnStatus.CONNECTING, VpnStatus.SWITCHING -> "App VPN: настроен • применяется"
        VpnStatus.DISCONNECTING -> "App VPN: настроен • VPN выключается"
        VpnStatus.CONNECTED -> "App VPN: настроен • scope TUN не подтверждён"
        else -> "App VPN: настроен • VPN выключен"
    }
}

fun appVpnCountText(count: Int): String {
    val word = when {
        count % 100 in 11..14 -> "приложений"
        count % 10 == 1 -> "приложение"
        count % 10 in 2..4 -> "приложения"
        else -> "приложений"
    }
    return "$count $word"
}
