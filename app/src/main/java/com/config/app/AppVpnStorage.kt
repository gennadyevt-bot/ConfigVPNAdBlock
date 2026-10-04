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
            .putString(SERVER_ID_KEY, serverId)
            .apply()
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
        private const val ENABLED_KEY = "app_vpn_enabled"
        private const val SERVER_ID_KEY = "app_vpn_server_id"
    }
}