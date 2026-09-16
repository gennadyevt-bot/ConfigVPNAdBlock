package com.config.app

import android.content.Context
import android.content.Intent
import androidx.core.content.FileProvider
import org.json.JSONArray
import java.io.File

class ServerBackupManager(private val context: Context) {

    private val storage = ServerStorage(context)

    fun shareBackup() {
        val servers = storage.loadServers()
        val jsonArray = JSONArray()
        servers.forEach { server ->
            val obj = org.json.JSONObject().apply {
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
            }
            jsonArray.put(obj)
        }

        val file = File(context.cacheDir, "config_backup.json")
        file.writeText(jsonArray.toString(2))

        val uri = FileProvider.getUriForFile(context, "${context.packageName}.provider", file)
        val intent = Intent(Intent.ACTION_SEND).apply {
            type = "application/json"
            putExtra(Intent.EXTRA_STREAM, uri)
            putExtra(Intent.EXTRA_SUBJECT, "Config Backup")
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        context.startActivity(Intent.createChooser(intent, "Share backup"))
    }
}
