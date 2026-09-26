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

    companion object {
        private const val REQ_INSTALL_CERT = 42
    }

    private lateinit var prefs: SharedPreferences
    private lateinit var sw: SwitchCompat
    private lateinit var tvStatus: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_adblock)
        prefs = getSharedPreferences("app_prefs", MODE_PRIVATE)
        sw = findViewById(R.id.swAdBlockMain)
        tvStatus = findViewById(R.id.tvAdBlockStatusMain)
        sw.isChecked = prefs.getBoolean("adblock_enabled", true)
        updateStatus()
        sw.setOnCheckedChangeListener { _, on ->
            prefs.edit().putBoolean("adblock_enabled", on).apply()
            if (on) thread { runCatching { UnifiedAdBlock.startFromUi(this@AdBlockActivity) } }
            updateStatus()
        }
        findViewById<android.view.View>(R.id.btnInstallCert).setOnClickListener { installCert() }
        findViewById<android.view.View>(R.id.btnResetCert).setOnClickListener { resetCert() }
        findViewById<android.view.View>(R.id.btnAdBlockLog).setOnClickListener { showLog() }
    }

    private fun installCert() {
        thread {
            try {
                val dir = filesDir
                val f = File(dir, "ca.crt")
                if (!f.exists()) {
                    mitm.Mitm.ensureCA(dir.absolutePath)
                }
                val bytes = f.readBytes()
                runOnUiThread {
                    val i = android.security.KeyChain.createInstallIntent()
                    i.putExtra(android.security.KeyChain.EXTRA_CERTIFICATE, bytes)
                    i.putExtra(android.security.KeyChain.EXTRA_NAME, "Config VPN AdBlock CA")
                    startActivityForResult(i, REQ_INSTALL_CERT)
                }
            } catch (t: Throwable) {
                runOnUiThread {
                    Toast.makeText(this, "Ошибка сертификата: " + (t.message ?: t.javaClass.simpleName), Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: android.content.Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQ_INSTALL_CERT && resultCode == RESULT_OK) {
            // Android не даёт приложению включить сертификат самому (защита ОС).
            // Ведём пользователя на экран сертификатов — там один тап.
            Toast.makeText(
                this,
                "Сертификат установлен. ВКЛЮЧИТЕ его: вкладка «Пользовательские» → Config VPN AdBlock CA → переключатель.",
                Toast.LENGTH_LONG
            ).show()
            // сразу на экран списка сертификатов (там переключатель), запасной — общая Безопасность
            runCatching {
                startActivity(android.content.Intent().setComponent(
                    android.content.ComponentName(
                        "com.android.settings",
                        "com.android.settings.Settings\$TrustedCredentialsSettingsActivity"
                    )
                ))
            }.onFailure {
                runCatching { startActivity(android.content.Intent(android.provider.Settings.ACTION_SECURITY_SETTINGS)) }
            }
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
        val text = if (lines.isEmpty()) "Журнал пуст. Включите VPN и подождите несколько секунд." else lines.joinToString("\n")
        AlertDialog.Builder(this)
            .setTitle("Журнал AdBlock")
            .setMessage(text)
            .setPositiveButton("OK", null)
            .show()
    }

    private fun updateStatus() {
        val on = prefs.getBoolean("adblock_enabled", true)
        tvStatus.text = if (on) "Включено (DNS/SNI/HTTPS фильтр)" else "Отключено"
        tvStatus.setTextColor(if (on) 0xFF8BC34A.toInt() else 0xFFB0BEC5.toInt())
    }
}
