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

        fun jsonToServer(json: JSONObject): ServerInfo? {
            return try {
                ServerInfo(
                    id = json.optString("id", ""),
                    name = json.optString("name", "Server"),
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
                    includedApps = json.optJSONArray("includedApps")?.let { arr ->
                        (0 until arr.length()).map { arr.getString(it) }
                    } ?: emptyList(),
                    excludedApps = json.optJSONArray("excludedApps")?.let { arr ->
                        (0 until arr.length()).map { arr.getString(it) }
                    } ?: emptyList()
                )
            } catch (e: Exception) {
                null
            }
        }

        fun serverToJson(server: ServerInfo): JSONObject {
            val json = JSONObject()
            json.put("id", server.id)
            json.put("name", server.name)
            json.put("country", server.country)
            json.put("flagEmoji", server.flagEmoji)
            json.put("interfaceAddress", server.interfaceAddress)
            json.put("interfaceDns", server.interfaceDns)
            json.put("interfaceMtu", server.interfaceMtu)
            json.put("interfacePrivateKey", server.interfacePrivateKey)
            json.put("peerPublicKey", server.peerPublicKey)
            json.put("peerPresharedKey", server.peerPresharedKey)
            json.put("peerAllowedIPs", server.peerAllowedIPs)
            json.put("peerEndpoint", server.peerEndpoint)
            json.put("peerPersistentKeepalive", server.peerPersistentKeepalive)
            json.put("jc", server.jc)
            json.put("jmin", server.jmin)
            json.put("jmax", server.jmax)
            json.put("s1", server.s1)
            json.put("s2", server.s2)
            json.put("h1", server.h1)
            json.put("h2", server.h2)
            json.put("h3", server.h3)
            json.put("h4", server.h4)
            json.put("includedApps", JSONArray(server.includedApps))
            json.put("excludedApps", JSONArray(server.excludedApps))
            return json
        }
    }

    fun loadServers(): List<ServerInfo> {
        val servers = mutableListOf<ServerInfo>()
        val savedJson = prefs.getString(KEY_SERVERS, null) ?: return servers

        try {
            val jsonArray = JSONArray(savedJson)
            for (i in 0 until jsonArray.length()) {
                jsonToServer(jsonArray.getJSONObject(i))?.let { servers.add(it) }
            }
        } catch (e: Exception) {
        }

        return servers
    }

    fun saveServers(servers: List<ServerInfo>) {
        val jsonArray = JSONArray()
        servers.forEach { server ->
            jsonArray.put(serverToJson(server))
        }
        prefs.edit().putString(KEY_SERVERS, jsonArray.toString()).apply()
    }

    fun getServerById(serverId: String): ServerInfo? {
        return loadServers().find { it.id == serverId }
    }
}
