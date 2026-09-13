package com.config.app

import android.content.Context

// Встроенный (зашитый) read-only сервер: лежит в assets как обычный .conf,
// отображается как "Profile 1". Доступен и в главном списке, и в App VPN.
object EmbeddedServers {

    private val builtin = listOf(
        "server1.conf" to "Profile 1"
    )

    fun load(context: Context): List<ServerInfo> {
        return builtin.mapIndexed { index, (assetName, displayName) ->
            try {
                val text = context.assets.open(assetName).bufferedReader().use { it.readText() }
                WgConfigParser.parse(text)?.copy(id = "emb_$index", name = displayName)
            } catch (e: Exception) {
                null
            }
        }.filterNotNull()
    }

    fun all(context: Context): List<ServerInfo> = load(context) + ServerStorage(context).loadServers()
}
