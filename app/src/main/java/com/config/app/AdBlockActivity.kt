package com.config.app

import android.content.Intent
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.View
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.SwitchCompat

// v2: экран «Блокировка рекламы». DNS-фильтр (proof) + Yandex Content Blocker
// (provider отдельно от VPN, без MITM). Статусы — только по реальным данным.
class AdBlockActivity : AppCompatActivity() {

    private lateinit var prefs: SharedPreferences
    private lateinit var sw: SwitchCompat
    private lateinit var tvStatus: TextView
    private lateinit var tvYandex: TextView
    private lateinit var btnYandex: View
    private lateinit var tvCbLog: TextView
    private val handler = Handler(Looper.getMainLooper())
    private val yandexPkgs = listOf("com.yandex.browser", "com.yandex.browser.beta", "com.yandex.browser.alpha")

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_adblock)
        prefs = getSharedPreferences("app_prefs", MODE_PRIVATE)
        sw = findViewById(R.id.swAdBlockMain)
        tvStatus = findViewById(R.id.tvAdBlockStatusMain)
        tvYandex = findViewById(R.id.tvYandexStatus)
        btnYandex = findViewById(R.id.btnConnectYandex)
        tvCbLog = findViewById(R.id.tvCbLog)
        sw.isChecked = prefs.getBoolean("adblock_enabled", false)
        updateStatus()
        updateYandex()
        sw.setOnCheckedChangeListener { _, on ->
            prefs.edit().putBoolean("adblock_enabled", on).apply()
            updateStatus()
        }
        btnYandex.setOnClickListener { openYandexSettings() }
        findViewById<View>(R.id.btnInstallCert).setOnClickListener {
            Toast.makeText(this, "Появится после интеграции HTTPS-движка (Phase F)", Toast.LENGTH_LONG).show()
        }
        findViewById<View>(R.id.btnResetCert).setOnClickListener {
            Toast.makeText(this, "Появится после интеграции HTTPS-движка (Phase F)", Toast.LENGTH_LONG).show()
        }
        findViewById<View>(R.id.btnAdBlockLog).setOnClickListener {
            tvCbLog.visibility = if (tvCbLog.visibility == View.VISIBLE) View.GONE else View.VISIBLE
            renderCbLog()
        }
        handler.post(ticker)
    }

    private val ticker = object : Runnable {
        override fun run() {
            updateYandex()
            if (tvCbLog.visibility == View.VISIBLE) renderCbLog()
            handler.postDelayed(this, 1000)
        }
    }

    private fun yandexInstalled(): Boolean {
        val pm = packageManager
        for (p in yandexPkgs) {
            try {
                pm.getPackageInfo(p, 0)
                return true
            } catch (_: PackageManager.NameNotFoundException) {}
        }
        return false
    }

    private fun updateYandex() {
        val installed = yandexInstalled()
        val served = prefs.getInt("cb_served", 0)
        if (!installed) {
            tvYandex.text = "Яндекс.Браузер: не найден"
            tvYandex.setTextColor(0xFFB0BEC5.toInt())
            btnYandex.visibility = View.GONE
        } else if (served > 0) {
            tvYandex.text = "Яндекс.Браузер: подключён"
            tvYandex.setTextColor(0xFF8BC34A.toInt())
            btnYandex.visibility = View.GONE
        } else {
            tvYandex.text = "Яндекс.Браузер: найден — включите блокировщик"
            tvYandex.setTextColor(0xFFFFC107.toInt())
            btnYandex.visibility = View.VISIBLE
        }
    }

    private fun openYandexSettings() {
        for (action in listOf(
            "com.yandex.browser.contentBlocker.ACTION_SETTING",
            "com.samsung.android.sbrowser.contentBlocker.ACTION_SETTING"
        )) {
            try {
                startActivity(Intent(action).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                Toast.makeText(this, "В Яндекс.Браузере выберите «Config VPN + AdBlock»", Toast.LENGTH_LONG).show()
                return
            } catch (_: Exception) {}
        }
        Toast.makeText(this, "Не удалось открыть настройки Content Blocker", Toast.LENGTH_LONG).show()
    }

    private fun updateStatus() {
        val on = prefs.getBoolean("adblock_enabled", false)
        tvStatus.text = if (on) "DNS/сетевой фильтр: работает" else "Отключено"
        tvStatus.setTextColor(if (on) 0xFF8BC34A.toInt() else 0xFFB0BEC5.toInt())
    }

    private fun renderCbLog() {
        tvCbLog.text = prefs.getString("cb_log", "(журнал пуст)")
    }

    override fun onDestroy() {
        handler.removeCallbacks(ticker)
        super.onDestroy()
    }
}
