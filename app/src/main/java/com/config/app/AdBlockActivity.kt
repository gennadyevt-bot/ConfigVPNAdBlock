package com.config.app

import android.content.SharedPreferences
import android.os.Bundle
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.SwitchCompat
import java.io.File
import kotlin.concurrent.thread

// Экран «Блокировка рекламы»: движок beta7 интегрирован (DNS/SNI/HTTPS через VPN-тракт).
class AdBlockActivity : AppCompatActivity() {

    private lateinit var prefs: SharedPreferences
    private lateinit var sw: SwitchCompat
    private lateinit var tvStatus: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_adblock)
        prefs = getSharedPreferences("app_prefs", MODE_PRIVATE)
        sw = findViewById(R.id.swAdBlockMain)
        tvStatus = findViewById(R.id.tvAdBlockStatusMain)
        sw.isChecked = prefs.getBoolean("adblock_enabled", false)
        updateStatus()
        sw.setOnCheckedChangeListener { _, on ->
            prefs.edit().putBoolean("adblock_enabled", on).apply()
            Toast.makeText(this, "Переподключите VPN для применения", Toast.LENGTH_LONG).show()
            updateStatus()
        }
        findViewById<android.view.View>(R.id.btnInstallCert).setOnClickListener { installCert() }
        findViewById<android.view.View>(R.id.btnResetCert).setOnClickListener { resetCert() }
        findViewById<android.view.View>(R.id.btnAdBlockLog).setOnClickListener { startActivity(android.content.Intent(this, AdBlockJournalActivity::class.java)) }
        findViewById<android.view.View>(R.id.btnYandexBlocker).setOnClickListener { openYandexBlocker() }
        if (intent.getBooleanExtra("show_log", false)) showLog()
    }

    private fun openYandexBlocker() {
        val actions = listOf(
            "com.yandex.browser.contentBlocker.ACTION_SETTING",
            "com.samsung.android.sbrowser.contentBlocker.ACTION_SETTING"
        )
        val packages = listOf("com.yandex.browser", "com.yandex.browser.beta", "com.yandex.browser.alpha")
        for (pkg in packages) {
            for (action in actions) {
                try {
                    startActivity(android.content.Intent(action).setPackage(pkg))
                    AdBlockLog.add("YANDEX_CB_OPEN_SETTINGS $pkg")
                    return
                } catch (_: android.content.ActivityNotFoundException) { }
            }
        }
        AdBlockLog.add("YANDEX_CB_OPEN_SETTINGS unavailable")
        Toast.makeText(this, "В Яндексе откройте Настройки → Блокировка содержимого → Расширения для блокировки и выберите Config VPN + AdBlock", Toast.LENGTH_LONG).show()
        packageManager.getLaunchIntentForPackage("com.yandex.browser")?.let { startActivity(it) }
    }

    private fun installCert() {
        try {
            val pem = mitm.Mitm.caCertPem(filesDir.absolutePath)
            val name = "ConfigVPNAdBlock-CA.crt"
            if (android.os.Build.VERSION.SDK_INT >= 29) {
                val values = android.content.ContentValues().apply {
                    put(android.provider.MediaStore.Downloads.DISPLAY_NAME, name)
                    put(android.provider.MediaStore.Downloads.MIME_TYPE, "application/x-x509-ca-cert")
                    put(android.provider.MediaStore.Downloads.RELATIVE_PATH, android.os.Environment.DIRECTORY_DOWNLOADS)
                }
                val uri = contentResolver.insert(android.provider.MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
                if (uri == null) { Toast.makeText(this, "Не удалось сохранить сертификат", Toast.LENGTH_LONG).show(); return }
                try {
                    val stream = contentResolver.openOutputStream(uri) ?: error("Не удалось открыть файл сертификата")
                    stream.use { it.write(pem) }
                } catch (e: Exception) {
                    contentResolver.delete(uri, null, null)
                    throw e
                }
            } else {
                val dir = android.os.Environment.getExternalStoragePublicDirectory(android.os.Environment.DIRECTORY_DOWNLOADS)
                dir.mkdirs()
                java.io.File(dir, name).writeBytes(pem)
            }
            prefs.edit().putString("ca_export_name", name).apply()
            Toast.makeText(this, "Сертификат сохранён в Загрузки. Дальше: Настройки -> Безопасность -> Установить сертификат -> CA-сертификат -> выбрать " + name, Toast.LENGTH_LONG).show()
            try { startActivity(android.content.Intent(android.provider.Settings.ACTION_SECURITY_SETTINGS)) } catch (_: Exception) {}
        } catch (e: Exception) {
            Toast.makeText(this, "Ошибка: " + (e.message ?: "?"), Toast.LENGTH_LONG).show()
        }
    }

    private fun resetCert() {
        thread {
            val deleted = listOf(File(filesDir, "ca.crt"), File(filesDir, "ca.key"))
                .map { it.exists() && it.delete() }
                .any { it }
            runOnUiThread {
                Toast.makeText(
                    this,
                    if (deleted) "Сертификат сброшен. Переподключите VPN для генерации нового."
                    else "Файлы CA не найдены (движок ещё не запускался?)",
                    Toast.LENGTH_LONG
                ).show()
            }
        }
    }

    private fun showLog() {
        val lines = AdBlockLog.snapshot()
        val native = if (UnifiedAdBlock.ready) runCatching {
            "Стек: ${mitm.Mitm.stackStats()}\nФильтр: ${mitm.Mitm.mitmStats()}\nПотоки: ${mitm.Mitm.flowLog()}"
        }.getOrElse { "Ошибка чтения движка: ${it.message}" } else "HTTPS-фильтр не запущен"
        val text = native + "\n\n" + if (lines.isEmpty()) "Журнал пуст. Подключите VPN." else lines.joinToString("\n")
        AlertDialog.Builder(this)
            .setTitle("Журнал AdBlock")
            .setMessage(text)
            .setPositiveButton("OK", null)
            .show()
    }

    private fun updateStatus() {
        val on = prefs.getBoolean("adblock_enabled", false)
        tvStatus.text = when {
            !on -> "Отключено"
            UnifiedAdBlock.ready -> "HTTPS-фильтр работает"
            else -> "Выбрано: включить. Переподключите VPN и проверьте журнал"
        }
        tvStatus.setTextColor(if (UnifiedAdBlock.ready) 0xFF8BC34A.toInt() else 0xFFB0BEC5.toInt())
    }
}
