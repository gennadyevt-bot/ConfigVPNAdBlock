package com.config.app

import android.content.SharedPreferences
import android.os.Bundle
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.SwitchCompat

// Phase B: экран «Блокировка рекламы». Переключатель хранит настройку
// adblock_enabled; движок пока НЕ подключён (Phase C+), статус честный.
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
            updateStatus()
        }
        findViewById<android.view.View>(R.id.btnInstallCert).setOnClickListener {
            Toast.makeText(this, "Появится после интеграции HTTPS-движка (Phase F)", Toast.LENGTH_LONG).show()
        }
        findViewById<android.view.View>(R.id.btnResetCert).setOnClickListener {
            Toast.makeText(this, "Появится после интеграции HTTPS-движка (Phase F)", Toast.LENGTH_LONG).show()
        }
        findViewById<android.view.View>(R.id.btnAdBlockLog).setOnClickListener {
            Toast.makeText(this, "Журнал появится вместе с движком (Phase C+)", Toast.LENGTH_LONG).show()
        }
    }

    private fun updateStatus() {
        val on = prefs.getBoolean("adblock_enabled", false)
        tvStatus.text = if (on)
            "Экспериментально включён — движок пока не подключён (Phase C)"
        else
            "Отключено"
        tvStatus.setTextColor(if (on) 0xFF8BC34A.toInt() else 0xFFB0BEC5.toInt())
    }
}
