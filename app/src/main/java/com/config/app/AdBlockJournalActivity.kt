package com.config.app

import android.os.Bundle
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import java.io.File
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

// Полный диагностический журнал (как в ConfigAdBlock beta7).
// Нативные вызовы — в background, каждый с таймаутом 1500 мс.
class AdBlockJournalActivity : AppCompatActivity() {

    private val exec = Executors.newCachedThreadPool()
    private lateinit var tv: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_adblock_journal)
        tv = findViewById(R.id.tvJournal)
        findViewById<android.view.View>(R.id.btnJournalRefresh).setOnClickListener { refresh() }
        findViewById<android.view.View>(R.id.btnJournalCopy).setOnClickListener { copyAll() }
        findViewById<android.view.View>(R.id.btnJournalClose).setOnClickListener { finish() }
        AdBlockLog.init(applicationContext)
        refresh()
    }

    private fun timed(f: () -> String): String {
        val fut = exec.submit(Callable { f() })
        return try { fut.get(1500, TimeUnit.MILLISECONDS) }
        catch (e: java.util.concurrent.TimeoutException) { "TIMEOUT (>1500 ms)" }
        catch (e: Throwable) { "ERROR: " + (e.message ?: e.javaClass.simpleName) }
    }

    private fun refresh() {
        tv.text = "Сбор диагностики..."
        thread {
            val prefs = getSharedPreferences("app_prefs", MODE_PRIVATE)
            val sb = StringBuilder()
            sb.append("=== STATUS ===\n")
            sb.append("version=").append(timed { packageManager.getPackageInfo(packageName, 0).versionName ?: "?" }).append("\n")
            sb.append("adblock_enabled=").append(prefs.getBoolean("adblock_enabled", false)).append("\n")
            sb.append("UnifiedAdBlock.running=").append(UnifiedAdBlock.running).append("\n")
            sb.append("UnifiedAdBlock.ready=").append(UnifiedAdBlock.ready).append("\n")
            sb.append("UnifiedAdBlock.SOURCE=").append(UnifiedAdBlock.SOURCE).append("\n")
            sb.append("ca.crt=").append(File(filesDir, "ca.crt").exists()).append("\n")
            sb.append("ca.key=").append(File(filesDir, "ca.key").exists()).append("\n")
            sb.append("\n=== NATIVE STATUS ===\n")
            sb.append("stackStats=").append(timed { mitm.Mitm.stackStats() }).append("\n")
            sb.append("tunStats=").append(timed { mitm.Mitm.tunStats() }).append("\n")
            sb.append("mitmStats=").append(timed { mitm.Mitm.mitmStats() }).append("\n")
            sb.append("caInfo=").append(timed { mitm.Mitm.caInfo() }).append("\n")
            sb.append("leafVerify=").append(timed { mitm.Mitm.leafVerify() }).append("\n")
            sb.append("selfTestResult=").append(timed { mitm.Mitm.selfTestResult() }).append("\n")
            sb.append("udpSeen=").append(timed { mitm.Mitm.udpSeen().toString() }).append(" ")
            sb.append("quicDrops=").append(timed { mitm.Mitm.quicDrops().toString() }).append(" ")
            sb.append("t443Seen=").append(timed { mitm.Mitm.t443Seen().toString() }).append("\n")
            sb.append("gpOk=").append(timed { mitm.Mitm.gpOk().toString() }).append(" ")
            sb.append("gpFail=").append(timed { mitm.Mitm.gpFail().toString() }).append(" ")
            sb.append("gpDial=").append(timed { mitm.Mitm.gpDial().toString() }).append("\n")
            sb.append("\n=== FLOW LOG ===\n")
            sb.append(timed { mitm.Mitm.flowLog() }).append("\n")
            sb.append("\n=== APP / DATAPATH LOG ===\n")
            sb.append(AdBlockLog.snapshot().takeLast(300).joinToString("\n")).append("\n")
            sb.append("\n=== VPN DEBUG.LOG ===\n")
            val dbg = File(filesDir, "debug.log")
            if (dbg.exists()) sb.append(dbg.readLines().takeLast(120).joinToString("\n")).append("\n")
            else sb.append("(debug.log отсутствует)\n")
            val text = sb.toString()
            runOnUiThread { tv.text = text }
        }
    }

    private fun copyAll() {
        val cm = getSystemService(CLIPBOARD_SERVICE) as android.content.ClipboardManager
        cm.setPrimaryClip(android.content.ClipData.newPlainText("adblock-journal", tv.text))
        Toast.makeText(this, "Журнал скопирован", Toast.LENGTH_SHORT).show()
    }
}
