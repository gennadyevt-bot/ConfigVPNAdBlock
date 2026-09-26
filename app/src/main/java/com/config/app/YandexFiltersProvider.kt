package com.config.app

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.net.Uri
import android.os.ParcelFileDescriptor
import java.io.File
import java.io.FileNotFoundException

/** Exposes the bundled AdBlock rules through the Content Blocker API used by Yandex Browser. */
class YandexFiltersProvider : ContentProvider() {
    override fun onCreate() = true

    @Synchronized
    override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor {
        if (mode != "r") throw FileNotFoundException("Read only")
        val ctx = context ?: throw FileNotFoundException("No context")
        val file = File(ctx.filesDir, "yandex_filters.txt")
        val installedAt = ctx.packageManager.getPackageInfo(ctx.packageName, 0).lastUpdateTime
        if (!file.exists() || file.lastModified() < installedAt) {
            val tmp = File(ctx.filesDir, "yandex_filters.tmp")
            try {
                tmp.bufferedWriter().use { writer ->
                    writer.appendLine("[Adblock Plus 2.0]")
                    ctx.assets.open("blocklist.txt").bufferedReader().useLines { lines ->
                        lines.forEach { raw ->
                            val line = raw.trim()
                            if (line.isEmpty() || line.startsWith("#") || line.startsWith("!")) return@forEach
                            val entry = if (line.startsWith("0.0.0.0 ")) line.substringAfter(' ').trim() else line
                            val domain = entry.substringBefore('/').lowercase()
                            if (domain == "0.0.0.0" || !domain.matches(Regex("[a-z0-9-]+(\\.[a-z0-9-]+)+"))) return@forEach
                            if ('/' in entry) writer.appendLine("||$domain^*/${entry.substringAfter('/')}")
                            else writer.appendLine("||$domain^")
                        }
                    }
                    ctx.assets.open("generic_cosmetic_rules.txt").bufferedReader().useLines { lines ->
                        lines.forEach { raw ->
                            val selector = raw.trim()
                            if (selector.isNotEmpty() && !selector.startsWith("!")) writer.appendLine("##$selector")
                        }
                    }
                    // Same Dzen specific rules as the original ConfigAdBlock provider.
                    ctx.assets.open("dzen_legacy_rules.txt").bufferedReader().useLines { lines ->
                        lines.forEach { raw ->
                            val rule = raw.trim()
                            if (rule.contains("##") || rule.startsWith("||") || rule.startsWith("@@")) writer.appendLine(rule)
                        }
                    }
                }
                if (file.exists() && !file.delete()) throw FileNotFoundException("Unable to replace filter list")
                if (!tmp.renameTo(file)) throw FileNotFoundException("Unable to publish filter list")
                AdBlockLog.add("YANDEX_CB_RULES_READY bytes=${file.length()}")
                runCatching {
                    ctx.sendBroadcast(android.content.Intent("com.samsung.android.sbrowser.contentBlocker.ACTION_UPDATE")
                        .setData(Uri.parse("package:${ctx.packageName}")))
                }
            } catch (e: Exception) {
                tmp.delete()
                throw FileNotFoundException("Unable to prepare browser filters: ${e.message}")
            }
        }
        AdBlockLog.add("YANDEX_CB_PROVIDER_OPEN")
        return ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY)
    }

    override fun getType(uri: Uri): String = "text/plain"
    override fun query(uri: Uri, projection: Array<out String>?, selection: String?, selectionArgs: Array<out String>?, sortOrder: String?): Cursor? = null
    override fun insert(uri: Uri, values: ContentValues?): Uri? = null
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = 0
    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<out String>?): Int = 0
}
