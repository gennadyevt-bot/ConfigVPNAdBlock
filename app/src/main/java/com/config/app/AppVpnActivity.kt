package com.config.app

import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.drawable.BitmapDrawable
import android.graphics.drawable.Drawable
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.Editable
import android.text.TextWatcher
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.ArrayAdapter
import android.widget.ProgressBar
import android.widget.Spinner
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.button.MaterialButtonToggleGroup
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class AppVpnActivity : AppCompatActivity() {

    private lateinit var rvApps: RecyclerView
    private lateinit var btnSave: Button
    private lateinit var etSearch: EditText
    private lateinit var tvScopeState: TextView
    private lateinit var tvCounter: TextView
    private lateinit var toggleMode: MaterialButtonToggleGroup
    private lateinit var progressBar: ProgressBar
    private lateinit var spServer: Spinner
    private lateinit var appVpnStorage: AppVpnStorage
    private var serversList = listOf<ServerInfo>()

    private val allApps = mutableListOf<AppInfo>()
    private val filteredApps = mutableListOf<AppInfo>()
    private val selectedPackages = mutableSetOf<String>()

    private var isIncludeMode = true

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_app_vpn)
        applyReleaseInsets()

        appVpnStorage = AppVpnStorage(this)

        rvApps = findViewById(R.id.rvApps)
        btnSave = findViewById(R.id.btnSave)
        etSearch = findViewById(R.id.etSearch)
        tvScopeState = findViewById(R.id.tvScopeState)
        tvCounter = findViewById(R.id.tvCounter)
        toggleMode = findViewById(R.id.toggleMode)
        progressBar = findViewById(R.id.progressBar)
        spServer = findViewById(R.id.spServer)

        rvApps.layoutManager = LinearLayoutManager(this)

        // Выбор конфига (сервера) для App VPN: встроенные + пользовательские
        serversList = EmbeddedServers.all(this)
        val serverNames = serversList.map { it.name.ifEmpty { it.peerEndpoint.ifEmpty { "Сервер" } } }
        val serverAdapter = ArrayAdapter(this, android.R.layout.simple_spinner_item, serverNames)
        serverAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        spServer.adapter = serverAdapter
        val savedServerId = appVpnStorage.getServerId()
        val savedIdx = serversList.indexOfFirst { it.id == savedServerId }
        spServer.setSelection(if (savedIdx >= 0) savedIdx else 0)

        initAppVpn()
    }

    private fun initAppVpn() {
        val savedSelected = appVpnStorage.getSelectedPackages()
        val savedExcluded = appVpnStorage.getExcludedPackages()
        isIncludeMode = appVpnStorage.configuration().mode == "INCLUDE"

        if (isIncludeMode) {
            selectedPackages.addAll(savedSelected)
            toggleMode.check(R.id.btnModeInclude)
        } else {
            selectedPackages.addAll(savedExcluded)
            toggleMode.check(R.id.btnModeExclude)
        }

        toggleMode.addOnButtonCheckedListener { _, checkedId, isChecked ->
            if (isChecked) {
                isIncludeMode = (checkedId == R.id.btnModeInclude)
                selectedPackages.clear()
                updateCounter()
                loadApps()
            }
        }

        etSearch.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {
                filterApps(s?.toString() ?: "")
            }
            override fun afterTextChanged(s: Editable?) {}
        })


        btnSave.setOnClickListener {
            val enabled = selectedPackages.isNotEmpty()
            val selIdx = spServer.selectedItemPosition
            val server = serversList.getOrNull(selIdx)
            appVpnStorage.saveConfiguration(selectedPackages, isIncludeMode,
                server?.id ?: appVpnStorage.getServerId())

            if (enabled) {
                val modeText = if (isIncludeMode) "через VPN" else "обход VPN"
                Toast.makeText(this, "Сохранено: ${selectedPackages.size} приложений ($modeText)", Toast.LENGTH_SHORT).show()
            } else {
                Toast.makeText(this, "App VPN отключен", Toast.LENGTH_SHORT).show()
            }
            // Builder application lists take effect only when a new TUN is established.
            // Saving while disconnected never requests a connection.
            VpnManager.getInstance(applicationContext).reapplyAppVpnScope()
            finish()
        }

        loadApps()
    }

    private fun loadApps() {
        progressBar.visibility = View.VISIBLE
        rvApps.visibility = View.GONE

        CoroutineScope(Dispatchers.IO).launch {
            val pm = packageManager
            // Сначала список пакетов в фоне; иконки НЕ грузим здесь —
            // loadIcon/getApplicationIcon вне главного потока первый раз
            // возвращает заглушки, реальные иконки появлялись только
            // при повторном открытии экрана.
            val pkgList = mutableListOf<Pair<String, String>>()

            try {
                val mainIntent = Intent(Intent.ACTION_MAIN, null)
                mainIntent.addCategory(Intent.CATEGORY_LAUNCHER)
                val resolveInfos = pm.queryIntentActivities(mainIntent, 0)
                val seen = mutableSetOf<String>()

                for (ri in resolveInfos) {
                    val pkg = ri.activityInfo.packageName
                    if (pkg == packageName || seen.contains(pkg)) continue
                    seen.add(pkg)
                    pkgList.add(pkg to ri.loadLabel(pm).toString())
                }
            } catch (e: Exception) {
                android.util.Log.e("AppVpn", "Load apps failed: ${e.message}", e)
            }

            withContext(Dispatchers.Main) {
                val appList = pkgList.map { (pkg, label) ->
                    val icon = try { pm.getApplicationIcon(pkg) } catch (e: Exception) { null }
                    AppInfo(pkg, label, icon, selectedPackages.contains(pkg))
                }.sortedBy { it.appName.lowercase() }

                allApps.clear()
                allApps.addAll(appList)
                filteredApps.clear()
                filteredApps.addAll(appList)
                progressBar.visibility = View.GONE
                rvApps.visibility = View.VISIBLE
                updateCounter()
                setupAdapter()
                // Обход прогрева кэша PackageManager: первый запрос иконок
                // в процессе может вернуть заглушки, кэш прогревается после
                // первого прохода. Перезагружаем иконки автоматически —
                // без ручного закрытия/открытия окна.
                iconRetryCount = 0
                iconHandler.postDelayed({ refreshIcons() }, 700)
            }
        }
    }

    private val iconHandler = Handler(Looper.getMainLooper())
    private var iconRetryCount = 0

    private fun refreshIcons() {
        val pm = packageManager
        var changed = false
        for (app in allApps) {
            val icon = try { pm.getApplicationIcon(app.packageName) } catch (e: Exception) { null }
            if (icon != null && !isDefaultIcon(pm, icon)) {
                if (app.icon !== icon) { app.icon = icon; changed = true }
            } else if (icon == null) {
                changed = true // попробуем ещё раз на следующем проходе
            }
        }
        if (changed) rvApps.adapter?.notifyDataSetChanged()
        iconRetryCount++
        // Повторяем до 5 раз с интервалом, пока все иконки не станут настоящими
        if (changed && iconRetryCount < 5) {
            iconHandler.postDelayed({ refreshIcons() }, 700)
        }
    }

    private fun isDefaultIcon(pm: PackageManager, icon: Drawable): Boolean {
        val def = pm.defaultActivityIcon ?: return false
        return if (icon is BitmapDrawable && def is BitmapDrawable) icon.bitmap == def.bitmap else false
    }

    private fun setupAdapter() {
        rvApps.adapter = AppListAdapter(filteredApps) { app, isChecked ->
            if (isChecked) {
                selectedPackages.add(app.packageName)
            } else {
                selectedPackages.remove(app.packageName)
            }
            allApps.find { it.packageName == app.packageName }?.isSelected = isChecked
            updateCounter()
        }
    }

    private fun filterApps(query: String) {
        val q = query.lowercase().trim()
        filteredApps.clear()
        if (q.isEmpty()) {
            filteredApps.addAll(allApps)
        } else {
            filteredApps.addAll(allApps.filter {
                it.appName.lowercase().contains(q) || it.packageName.lowercase().contains(q)
            })
        }
        rvApps.adapter?.notifyDataSetChanged()
    }

    private val statusHandler = Handler(Looper.getMainLooper())
    private val statusTicker = object : Runnable {
        override fun run() {
            val config = appVpnStorage.configuration()
            val mode = if (config.mode == "INCLUDE") "выбранные приложения через VPN"
                else "все приложения, кроме выбранных, через VPN"
            val state = appVpnStatusText(config).removePrefix("App VPN: ")
            val applied = appliedAppVpnScope()
            val tunState = if (applied?.active == true) applied.mode
                else if (VpnManager.globalStatus == VpnStatus.CONNECTED) "не подтверждён" else "VPN выключен"
            tvScopeState.text = "Состояние: $state\nРежим: $mode\nПриложений: ${config.packages.size}\nПрименённый TUN: $tunState"
            statusHandler.postDelayed(this, 1000)
        }
    }

    override fun onResume() {
        super.onResume()
        statusHandler.post(statusTicker)
    }

    override fun onPause() {
        statusHandler.removeCallbacks(statusTicker)
        super.onPause()
    }

    private fun updateCounter() {
        tvCounter.text = "Выбрано: ${selectedPackages.size} • " +
            if (isIncludeMode) "через VPN" else "обход VPN"
    }

}
