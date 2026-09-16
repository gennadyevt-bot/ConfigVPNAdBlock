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
            jsonArray.put(ServerStorage.serverToJson(server))
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
