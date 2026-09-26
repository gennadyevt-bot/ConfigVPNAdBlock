package com.config.app

import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

// Постоянный журнал AdBlock: память + filesDir/adblock_journal.log.
// Timestamp у каждой строки, держим ~800 строк, переживает перезапуск.
object AdBlockLog {
    private const val MAX = 800
    private val buf = ArrayDeque<String>()
    private var logFile: File? = null
    private val ts = SimpleDateFormat("MM-dd HH:mm:ss.SSS", Locale.US)

    @Synchronized
    fun init(ctx: android.content.Context) {
        if (logFile != null) return
        logFile = File(ctx.filesDir, "adblock_journal.log")
        runCatching {
            logFile!!.readLines().forEach { buf.addLast(it) }
            while (buf.size > MAX) buf.removeFirst()
        }
        add("AdBlockLog.init file=" + logFile!!.absolutePath)
    }

    @Synchronized
    fun add(s: String) {
        val line = ts.format(Date()) + " " + s
        buf.addLast(line)
        var trimmed = false
        while (buf.size > MAX) { buf.removeFirst(); trimmed = true }
        android.util.Log.d("ADBLOCK", line)
        val f = logFile ?: return
        runCatching {
            if (trimmed) f.writeText(buf.joinToString("\n") + "\n")
            else f.appendText(line + "\n")
        }
    }

    @Synchronized
    fun snapshot(): List<String> = buf.toList()
}
