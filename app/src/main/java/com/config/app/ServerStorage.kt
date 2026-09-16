package com.config.app

import android.content.Context
import android.content.SharedPreferences
import org.json.JSONArray
import org.json.JSONObject

class ServerStorage(context: Context) {

    private val prefs: SharedPreferences = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    companion object {
        private const val PREFS_NAME = "config_servers"
        private const val KEY_SERVERS = "servers_list"

        // Все чтения — через opt/optJSONArray: записи, сохранённые старыми
        // версиями (без MTU, без AWG-параметров, без списков приложений),
        // обязаны загружаться, а не превращаться в null. null возвращаем
        // только для записи без ключевого материала — это не сервер, а мусор.
        fun jsonToServer(json: JSONObject): ServerInfo? {
            return try {
                val info = ServerInfo(
                    id = json.optString("id", ""),
                    name = json.optString("name", ""),
                    country = json.optString("country", ""),
                    flagEmoji = json.optString("flagEmoji", ""),
                    interfaceAddress = json.optString("interfaceAddress", ""),
                    interfaceDns = json.optString("interfaceDns", "1.1.1.1, 8.8.8.8"),
                    interfaceMtu = json.optString("interfaceMtu", ""),
                    interfacePrivateKey = json.optString("interfacePrivateKey", ""),
                    peerPublicKey = json.optString("peerPublicKey", ""),
                    peerPresharedKey = json.optString("peerPresharedKey", ""),
                    peerAllowedIPs = json.optString("peerAllowedIPs", "0.0.0.0/0"),
                    peerEndpoint = json.optString("peerEndpoint", ""),
                    peerPersistentKeepalive = json.optString("peerPersistentKeepalive", "25"),
                    jc = json.optString("jc", ""),
                    jmin = json.optString("jmin", ""),
                    jmax = json.optString("jmax", ""),
                    s1 = json.optString("s1", ""),
                    s2 = json.optString("s2", ""),
                    h1 = json.optString("h1", ""),
                    h2 = json.optString("h2", ""),
                    h3 = json.optString("h3", ""),
                    h4 = json.optString("h4", ""),
                    includedApps = json.optJSONArray("includedApps")?.toStringList() ?: emptyList(),
                    excludedApps = json.optJSONArray("excludedApps")?.toStringList() ?: emptyList()
                )
                if (info.id.isEmpty() || info.interfacePrivateKey.isEmpty() ||
                    info.peerPublicKey.isEmpty() || info.peerEndpoint.isEmpty()
                ) null else info
            } catch (e: Exception) {
                null
            }
        }

        fun serverToJson(server: ServerInfo): JSONObject {
            return JSONObject().apply {
                put("id", server.id)
                put("name", server.name)
                put("country", server.country)
                put("flagEmoji", server.flagEmoji)
                put("interfaceAddress", server.interfaceAddress)
                put("interfaceDns", server.interfaceDns)
                put("interfaceMtu", server.interfaceMtu)
                put("interfacePrivateKey", server.interfacePrivateKey)
                put("peerPublicKey", server.peerPublicKey)
                put("peerPresharedKey", server.peerPresharedKey)
                put("peerAllowedIPs", server.peerAllowedIPs)
                put("peerEndpoint", server.peerEndpoint)
                put("peerPersistentKeepalive", server.peerPersistentKeepalive)
                put("jc", server.jc)
                put("jmin", server.jmin)
                put("jmax", server.jmax)
                put("s1", server.s1)
                put("s2", server.s2)
                put("h1", server.h1)
                put("h2", server.h2)
                put("h3", server.h3)
                put("h4", server.h4)
                put("includedApps", JSONArray(server.includedApps))
                put("excludedApps", JSONArray(server.excludedApps))
            }
        }

        private fun JSONArray.toStringList(): List<String> {
            val out = mutableListOf<String>()
            for (i in 0 until length()) {
                val s = optString(i, "")
                if (s.isNotEmpty()) out.add(s)
            }
            return out
        }
    }

    fun saveServers(servers: List<ServerInfo>) {
        val jsonArray = JSONArray()
        servers.forEach { server ->
            jsonArray.put(serverToJson(server))
        }
        prefs.edit().putString(KEY_SERVERS, jsonArray.toString()).apply()
    }

    fun loadServers(): MutableList<ServerInfo> {
        val jsonString = prefs.getString(KEY_SERVERS, null) ?: return mutableListOf()
        val servers = mutableListOf<ServerInfo>()
        try {
            val jsonArray = JSONArray(jsonString)
            for (i in 0 until jsonArray.length()) {
                // optJSONObject: одна повреждённая запись не должна обрывать
                // загрузку остальных (getJSONObject бросал и терял весь список)
                jsonArray.optJSONObject(i)?.let { obj ->
                    jsonToServer(obj)?.let { servers.add(it) }
                }
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return servers
    }

    fun addServer(server: ServerInfo) {
        val servers = loadServers()
        servers.add(server)
        saveServers(servers)
    }

    fun removeServer(serverId: String) {
        val servers = loadServers()
        servers.removeAll { it.id == serverId }
        saveServers(servers)
    }

    fun clearAll() {
        prefs.edit().remove(KEY_SERVERS).apply()
    }
}
