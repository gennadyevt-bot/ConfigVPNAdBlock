package com.config.app

import android.app.Activity
import android.app.AlertDialog
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.LayoutInflater
import android.widget.Button
import android.widget.EditText
import android.widget.ImageView
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.view.GravityCompat
import androidx.drawerlayout.widget.DrawerLayout
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import android.view.View
import com.google.android.material.navigation.NavigationView
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import com.google.zxing.BinaryBitmap
import com.google.zxing.MultiFormatReader
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.HybridBinarizer

class MainActivity : AppCompatActivity() {

    private lateinit var vpnManager: VpnManager
    private lateinit var serverAdapter: ServerAdapter
    private lateinit var serverStorage: ServerStorage
    private lateinit var tvStatus: TextView
    private lateinit var rvServers: RecyclerView
    private lateinit var tvTrafficDown: TextView
    private lateinit var tvTrafficUp: TextView
    private lateinit var ivMenu: ImageView
    private lateinit var drawerLayout: DrawerLayout
    private lateinit var navView: NavigationView

    private var selectedServer: ServerInfo? = null
    private val servers = mutableListOf<ServerInfo>()

    // id встроенных read-only серверов (слоты 1-3): выглядят как обычные,
    // но редактирование/удаление/просмотр ключей недоступны
    private val embeddedIds = mutableSetOf<String>()

    private var currentDialogView: View? = null
    private var currentDialogPosition: Int = -1

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            selectedServer?.let { connectToServer(it) }
        } else {
            Toast.makeText(this, "Permission denied", Toast.LENGTH_SHORT).show()
        }
    }

    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { isGranted ->
        if (!isGranted) {
            Toast.makeText(this, "Notifications disabled — background mode may be unstable", Toast.LENGTH_LONG).show()
        }
    }

    private val qrScannerLauncher = registerForActivityResult(ScanContract()) { result ->
        if (result.contents != null) {
            val config = WgConfigParser.parse(result.contents)
            if (config != null) {
                fillDialogFields(config)
                Toast.makeText(this, "QR распознан: ${config.name}", Toast.LENGTH_SHORT).show()
            } else {
                Toast.makeText(this, "Неверный формат QR-кода", Toast.LENGTH_LONG).show()
            }
        }
    }

    private val filePickerLauncher = registerForActivityResult(
        ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        uri?.let { handleFileImport(it) }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        applyReleaseInsets()

        vpnManager = VpnManager.getInstance(this)
        serverStorage = ServerStorage(this)

        tvStatus = findViewById(R.id.tvStatus)
        rvServers = findViewById(R.id.rvServers)
        tvTrafficDown = findViewById(R.id.tvTrafficDown)
        tvTrafficUp = findViewById(R.id.tvTrafficUp)
        ivMenu = findViewById(R.id.ivMenu)
        drawerLayout = findViewById(R.id.drawerLayout)
        navView = findViewById(R.id.navView)
        navView.itemIconTintList = null

        requestNotificationPermission()
        loadServers()
        setupRecyclerView()
        setupVpnCallbacks()
        updateUiState(VpnStatus.DISCONNECTED)

        ivMenu.setOnClickListener {
            drawerLayout.openDrawer(GravityCompat.START)
        }

        // Phase B: индикатор/переключатель AdBlock на главном экране.
        // Хранит настройку adblock_enabled; движок пока не подключён (Phase C+).
        val adPrefs = getSharedPreferences("app_prefs", MODE_PRIVATE)
        val swAdBlock = findViewById<androidx.appcompat.widget.SwitchCompat>(R.id.swAdBlock)
        val tvAdBlockStatus = findViewById<android.widget.TextView>(R.id.tvAdBlockStatus)
        fun renderAdBlock(on: Boolean) {
            tvAdBlockStatus.text = if (on) "вкл (экспериментально)" else "выкл"
            tvAdBlockStatus.setTextColor(if (on) 0xFF8BC34A.toInt() else 0xFF9CCC9C.toInt())
        }
        renderAdBlock(adPrefs.getBoolean("adblock_enabled", false))
        swAdBlock.isChecked = adPrefs.getBoolean("adblock_enabled", false)
        swAdBlock.setOnCheckedChangeListener { _, on ->
            adPrefs.edit().putBoolean("adblock_enabled", on).apply()
            renderAdBlock(on)
            Toast.makeText(this, if (on) "AdBlock: включён (движок пока не активен)" else "AdBlock: выключен", Toast.LENGTH_SHORT).show()
        }

        navView.setNavigationItemSelectedListener { menuItem ->
            when (menuItem.itemId) {
                R.id.navAppVpn -> startActivity(android.content.Intent(this, AppVpnActivity::class.java))
                R.id.navDomainVpn -> startActivity(android.content.Intent(this, DomainVpnActivity::class.java))
                R.id.navAdBlock -> startActivity(android.content.Intent(this, AdBlockActivity::class.java))
                R.id.navBackup -> showBackupDialog()
                R.id.navAutoConnect -> showAutoConnectDialog()
                R.id.navGuide -> startActivity(android.content.Intent(this, com.config.app.GuideActivity::class.java))
                R.id.navOwnServer -> com.config.app.OwnServerSetup.show(this, serverStorage) { loadServers() }
                R.id.navCloudUpdate -> com.config.app.CloudServers.update(this, serverStorage) { loadServers() }
                R.id.navDebugLog -> {
                    val lf = java.io.File(filesDir, "debug.log")
                    val txt = if (lf.exists()) lf.readText().lines().takeLast(90).joinToString("\n") else "Лог пуст. Подключитесь к серверу."
                    val tv = android.widget.TextView(this)
                    tv.text = txt; tv.setTextIsSelectable(true); tv.setPadding(50, 40, 50, 40); tv.textSize = 11f
                    tv.movementMethod = android.text.method.ScrollingMovementMethod.getInstance()
                    androidx.appcompat.app.AlertDialog.Builder(this).setTitle("Журнал отладки").setView(tv).setPositiveButton("ОК", null).show()
                }
                R.id.navAbout -> {
                    val ver = try { packageManager.getPackageInfo(packageName, 0).versionName } catch (e: Exception) { "?" }
                    Toast.makeText(this, "Config VPN v" + ver + " | WireGuard + AmneziaWG", Toast.LENGTH_LONG).show()
                }
            }
            drawerLayout.closeDrawer(GravityCompat.START)
            true
        }

        // === АВТОВОССТАНОВЛЕНИЕ VPN ПРИ СТАРТЕ ===
        val vpnStateStorage = VpnStateStorage(this)
        if (vpnStateStorage.wasConnected()) {
            val lastServerId = vpnStateStorage.getLastServer()
            val lastServer = servers.find { it.id == lastServerId } ?: servers.firstOrNull { 
                it.interfacePrivateKey.isNotEmpty() && it.peerPublicKey.isNotEmpty() && it.peerEndpoint.isNotEmpty()
            }
            lastServer?.let {
                selectedServer = it
                serverAdapter.setSelectedServer(it.id)
                requestVpnPermissionAndConnect(it)
            }
        }
        // ==========================================

        val autoConnect = AutoConnectStorage(this)
        if (autoConnect.isEnabled()) {
            val validServer = servers.firstOrNull { hasValidConfig(it) }
            validServer?.let {
                selectedServer = it
                requestVpnPermissionAndConnect(it)
            }
        }

        val appVpnStorage = AppVpnStorage(this)
        if (appVpnStorage.isEnabled() && appVpnStorage.getSelectedPackages().isNotEmpty()) {
            AppMonitorService.start(this)
        }
    }

    private fun loadServers() {
        servers.clear()
        embeddedIds.clear()

        // Встроенные серверы (read-only) — Profile 1/2/3
        EmbeddedServers.load(this).forEach { emb ->
            servers.add(emb)
            embeddedIds.add(emb.id)
        }

        // Пользовательские слоты (до 5) — с миграцией: убираем из хранилища
        // дубликаты встроенных конфигов (сохранённые тестовой сборкой)
        val saved = serverStorage.loadServers().filter { userSrv ->
            embeddedIds.none { embId ->
                val emb = servers.firstOrNull { it.id == embId }
                emb != null && emb.interfacePrivateKey == userSrv.interfacePrivateKey
            }
        }.toMutableList()
        while (saved.size < 5) {
            saved.add(ServerInfo(id = "user_${saved.size}", name = "Empty Slot"))
        }
        servers.addAll(saved.take(5))
        serverStorage.saveServers(saved.take(5))
    }

    private fun saveUserServers() {
        serverStorage.saveServers(servers.filter { it.id !in embeddedIds })
    }

    

    private fun setupRecyclerView() {
        serverAdapter = ServerAdapter(
            servers,
            onConnectClick = { server ->
                if (!hasValidConfig(server)) {
                    Toast.makeText(this, "Add config first via +", Toast.LENGTH_SHORT).show()
                    return@ServerAdapter
                }
                selectedServer = server
                requestVpnPermissionAndConnect(server)
            },
            onStopClick = { _ ->
                vpnManager.disconnect()
            },
            onAddClick = { _, position ->
                if (servers.getOrNull(position)?.id in embeddedIds) return@ServerAdapter
                showAddServerDialog(servers[position], position)
            },
            onLongPress = { server, position ->
                if (server.id in embeddedIds) {
                    Toast.makeText(this, "Встроенный сервер: редактирование недоступно", Toast.LENGTH_SHORT).show()
                    return@ServerAdapter
                }
                if (hasValidConfig(server)) {
                    showEditServerDialog(server, position)
                } else {
                    showAddServerDialog(server, position)
                }
            }
        )
        rvServers.layoutManager = LinearLayoutManager(this)
        rvServers.adapter = serverAdapter
    }

    private fun setupVpnCallbacks() {
        vpnManager.onStatusChanged = { status ->
            updateUiState(status)
            serverAdapter.setStatus(status)
        }
        vpnManager.onServerChanged = { server ->
            server?.let {
                serverAdapter.setSelectedServer(it.id)
            } ?: run {
                serverAdapter.setSelectedServer(null)
            }
        }
    }

    private fun hasValidConfig(server: ServerInfo): Boolean {
        return server.interfacePrivateKey.isNotEmpty() &&
                server.peerPublicKey.isNotEmpty() &&
                server.peerEndpoint.isNotEmpty()
    }

    private fun requestVpnPermissionAndConnect(server: ServerInfo) {
        val consent = getSharedPreferences("privacy_consent", MODE_PRIVATE)
        if (!consent.getBoolean("vpn_v1", false)) {
            AlertDialog.Builder(this)
                .setTitle("Подключение VPN")
                .setMessage("Config VPN направляет выбранный сетевой трафик через VPN-сервер и шифрует его до сервера по WireGuard или AmneziaWG. Оператор выбранного сервера может видеть ваш IP-адрес, адреса назначений и незашифрованный трафик. Используйте сервер, которому доверяете. Приложение хранит конфигурации и ключи на устройстве; экспорт резервной копии включает ключи. Продолжить?")
                .setPositiveButton("Согласен") { _, _ ->
                    consent.edit().putBoolean("vpn_v1", true).apply()
                    requestVpnPermissionAndConnect(server)
                }
                .setNegativeButton("Отмена", null)
                .show()
            return
        }
        val intent = vpnManager.getPrepareIntent(this)
        if (intent != null) {
            vpnPermissionLauncher.launch(intent)
        } else {
            connectToServer(server)
        }
    }

    private fun connectToServer(server: ServerInfo) {
        vpnManager.connect(server)
    }

    private fun requestNotificationPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            when {
                ContextCompat.checkSelfPermission(this, android.Manifest.permission.POST_NOTIFICATIONS)
                        == PackageManager.PERMISSION_GRANTED -> { }
                shouldShowRequestPermissionRationale(android.Manifest.permission.POST_NOTIFICATIONS) -> {
                    Toast.makeText(this, "Notifications needed for stable background operation", Toast.LENGTH_LONG).show()
                    notificationPermissionLauncher.launch(android.Manifest.permission.POST_NOTIFICATIONS)
                }
                else -> {
                    notificationPermissionLauncher.launch(android.Manifest.permission.POST_NOTIFICATIONS)
                }
            }
        }
    }

    private fun startQrScan() {
        val options = ScanOptions()
        options.setPrompt("Наведите камеру на QR-код конфига")
        options.setBeepEnabled(true)
        options.setOrientationLocked(true)
        options.setCameraId(0)
        qrScannerLauncher.launch(options)
    }

    private fun pickFile() {
        filePickerLauncher.launch("*/*")
    }

    private fun handleFileImport(uri: Uri) {
        val mime = contentResolver.getType(uri)
        if (mime?.startsWith("image/") == true) {
            decodeQrFromImage(uri)
        } else {
            importConfigFromTextFile(uri)
        }
    }

    private fun importConfigFromTextFile(uri: Uri) {
        try {
            val inputStream = contentResolver.openInputStream(uri)
            val text = inputStream?.bufferedReader()?.use { it.readText() } ?: ""
            inputStream?.close()

            if (text.isEmpty()) {
                Toast.makeText(this, "Файл пуст", Toast.LENGTH_SHORT).show()
                return
            }

            val config = WgConfigParser.parse(text)
            if (config != null) {
                fillDialogFields(config)
                Toast.makeText(this, "Конфиг импортирован: ${config.name}", Toast.LENGTH_SHORT).show()
            } else {
                Toast.makeText(this, "Неверный формат конфига", Toast.LENGTH_SHORT).show()
            }
        } catch (e: Exception) {
            Toast.makeText(this, "Ошибка импорта: ${e.message}", Toast.LENGTH_SHORT).show()
        }
    }

    private fun decodeQrFromImage(uri: Uri) {
        try {
            val inputStream = contentResolver.openInputStream(uri)
            val bitmap = BitmapFactory.decodeStream(inputStream)
            inputStream?.close()

            if (bitmap == null) {
                Toast.makeText(this, "Не удалось загрузить изображение", Toast.LENGTH_SHORT).show()
                return
            }

            val width = bitmap.width
            val height = bitmap.height
            val pixels = IntArray(width * height)
            bitmap.getPixels(pixels, 0, width, 0, 0, width, height)

            val source = RGBLuminanceSource(width, height, pixels)
            val binaryBitmap = BinaryBitmap(HybridBinarizer(source))
            val reader = MultiFormatReader()
            val result = reader.decode(binaryBitmap)

            val config = WgConfigParser.parse(result.text)
            if (config != null) {
                fillDialogFields(config)
                Toast.makeText(this, "QR из файла распознан: ${config.name}", Toast.LENGTH_SHORT).show()
            } else {
                Toast.makeText(this, "Неверный формат QR-кода в файле", Toast.LENGTH_LONG).show()
            }
        } catch (e: Exception) {
            Toast.makeText(this, "QR не найден на изображении", Toast.LENGTH_SHORT).show()
        }
    }

    private fun showAddServerDialog(server: ServerInfo, position: Int) {
        val view = LayoutInflater.from(this).inflate(R.layout.dialog_add_server, null)
        currentDialogView = view
        currentDialogPosition = position

        val etName = view.findViewById<EditText>(R.id.etName)
        val etEndpoint = view.findViewById<EditText>(R.id.etEndpoint)
        val etPrivateKey = view.findViewById<EditText>(R.id.etPrivateKey)
        val etPublicKey = view.findViewById<EditText>(R.id.etPublicKey)
        val etAddress = view.findViewById<EditText>(R.id.etAddress)
        val etDns = view.findViewById<EditText>(R.id.etDns)
        val etPresharedKey = view.findViewById<EditText>(R.id.etPresharedKey)
        val etAllowedIPs = view.findViewById<EditText>(R.id.etAllowedIPs)
        val etPersistentKeepalive = view.findViewById<EditText>(R.id.etPersistentKeepalive)
        val etJc = view.findViewById<EditText>(R.id.etJc)
        val etJmin = view.findViewById<EditText>(R.id.etJmin)
        val etJmax = view.findViewById<EditText>(R.id.etJmax)
        val etS1 = view.findViewById<EditText>(R.id.etS1)
        val etS2 = view.findViewById<EditText>(R.id.etS2)
        val etH1 = view.findViewById<EditText>(R.id.etH1)
        val etH2 = view.findViewById<EditText>(R.id.etH2)
        val etH3 = view.findViewById<EditText>(R.id.etH3)
        val etH4 = view.findViewById<EditText>(R.id.etH4)
        val btnScanQr = view.findViewById<Button>(R.id.btnScanQr)
        val btnPickImage = view.findViewById<Button>(R.id.btnPickImage)

        btnScanQr.setOnClickListener { startQrScan() }
        btnPickImage.setOnClickListener { pickFile() }

        AlertDialog.Builder(this, R.style.DarkAlertDialog)
            .setView(view)
            .setPositiveButton("Add") { _, _ ->
                val name = etName.text.toString().trim()
                val endpoint = etEndpoint.text.toString().trim()
                val privateKey = etPrivateKey.text.toString().trim()
                val publicKey = etPublicKey.text.toString().trim()
                val address = etAddress.text.toString().trim().ifEmpty { "192.168.6.54/32" }
                val dns = etDns.text.toString().trim().ifEmpty { "1.1.1.1, 8.8.8.8" }
                val presharedKey = etPresharedKey.text.toString().trim()
                val allowedIPs = etAllowedIPs.text.toString().trim().ifEmpty { "0.0.0.0/0" }
                val persistentKeepalive = etPersistentKeepalive.text.toString().trim().ifEmpty { "25" }
                val jc = etJc.text.toString().trim().ifEmpty { "0" }
                val jmin = etJmin.text.toString().trim().ifEmpty { "0" }
                val jmax = etJmax.text.toString().trim().ifEmpty { "0" }
                val s1 = etS1.text.toString().trim().ifEmpty { "0" }
                val s2 = etS2.text.toString().trim().ifEmpty { "0" }
                val h1 = etH1.text.toString().trim().ifEmpty { "0" }
                val h2 = etH2.text.toString().trim().ifEmpty { "0" }
                val h3 = etH3.text.toString().trim().ifEmpty { "0" }
                val h4 = etH4.text.toString().trim().ifEmpty { "0" }

                if (privateKey.isEmpty() || publicKey.isEmpty() || endpoint.isEmpty()) {
                    Toast.makeText(this, "PrivateKey, PublicKey и Endpoint обязательны", Toast.LENGTH_SHORT).show()
                    return@setPositiveButton
                }

                val updated = server.copy(
                    name = name.ifEmpty { "Server ${position + 1}" },
                    interfaceAddress = address,
                    interfaceDns = dns,
                    interfacePrivateKey = privateKey,
                    peerPublicKey = publicKey,
                    peerPresharedKey = presharedKey,
                    peerEndpoint = endpoint,
                    peerAllowedIPs = allowedIPs,
                    peerPersistentKeepalive = persistentKeepalive,
                    jc = jc, jmin = jmin, jmax = jmax,
                    s1 = s1, s2 = s2,
                    h1 = h1, h2 = h2, h3 = h3, h4 = h4
                )
                servers[position] = updated
                saveUserServers()
                serverAdapter.notifyItemChanged(position)
                Toast.makeText(this, "Config added", Toast.LENGTH_SHORT).show()
            }
            .setNeutralButton("Очистить") { _, _ ->
                fun clearAll(v: android.view.View) {
                    when (v) {
                        is android.widget.EditText -> v.setText("")
                        is android.view.ViewGroup -> for (i in 0 until v.childCount) clearAll(v.getChildAt(i))
                    }
                }
                clearAll(view)
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun showEditServerDialog(server: ServerInfo, position: Int) {
        val view = LayoutInflater.from(this).inflate(R.layout.dialog_add_server, null)
        currentDialogView = view
        currentDialogPosition = position

        val etName = view.findViewById<EditText>(R.id.etName)
        val etEndpoint = view.findViewById<EditText>(R.id.etEndpoint)
        val etPrivateKey = view.findViewById<EditText>(R.id.etPrivateKey)
        val etPublicKey = view.findViewById<EditText>(R.id.etPublicKey)
        val etAddress = view.findViewById<EditText>(R.id.etAddress)
        val etDns = view.findViewById<EditText>(R.id.etDns)
        val etPresharedKey = view.findViewById<EditText>(R.id.etPresharedKey)
        val etAllowedIPs = view.findViewById<EditText>(R.id.etAllowedIPs)
        val etPersistentKeepalive = view.findViewById<EditText>(R.id.etPersistentKeepalive)
        val etJc = view.findViewById<EditText>(R.id.etJc)
        val etJmin = view.findViewById<EditText>(R.id.etJmin)
        val etJmax = view.findViewById<EditText>(R.id.etJmax)
        val etS1 = view.findViewById<EditText>(R.id.etS1)
        val etS2 = view.findViewById<EditText>(R.id.etS2)
        val etH1 = view.findViewById<EditText>(R.id.etH1)
        val etH2 = view.findViewById<EditText>(R.id.etH2)
        val etH3 = view.findViewById<EditText>(R.id.etH3)
        val etH4 = view.findViewById<EditText>(R.id.etH4)
        val btnScanQr = view.findViewById<Button>(R.id.btnScanQr)
        val btnPickImage = view.findViewById<Button>(R.id.btnPickImage)

        etName.setText(server.name)
        etEndpoint.setText(server.peerEndpoint)
        etPrivateKey.setText(server.interfacePrivateKey)
        etPublicKey.setText(server.peerPublicKey)
        etAddress.setText(server.interfaceAddress)
        etDns.setText(server.interfaceDns)
        etPresharedKey.setText(server.peerPresharedKey)
        etAllowedIPs.setText(server.peerAllowedIPs)
        etPersistentKeepalive.setText(server.peerPersistentKeepalive)
        etJc.setText(server.jc)
        etJmin.setText(server.jmin)
        etJmax.setText(server.jmax)
        etS1.setText(server.s1)
        etS2.setText(server.s2)
        etH1.setText(server.h1)
        etH2.setText(server.h2)
        etH3.setText(server.h3)
        etH4.setText(server.h4)

        btnScanQr.setOnClickListener { startQrScan() }
        btnPickImage.setOnClickListener { pickFile() }

        AlertDialog.Builder(this, R.style.DarkAlertDialog)
            .setView(view)
            .setPositiveButton("Save") { _, _ ->
                val updated = server.copy(
                    name = etName.text.toString().trim().ifEmpty { server.name },
                    interfaceAddress = etAddress.text.toString().trim().ifEmpty { server.interfaceAddress },
                    interfaceDns = etDns.text.toString().trim().ifEmpty { server.interfaceDns },
                    interfacePrivateKey = etPrivateKey.text.toString().trim().ifEmpty { server.interfacePrivateKey },
                    peerPublicKey = etPublicKey.text.toString().trim().ifEmpty { server.peerPublicKey },
                    peerPresharedKey = etPresharedKey.text.toString().trim(),
                    peerEndpoint = etEndpoint.text.toString().trim().ifEmpty { server.peerEndpoint },
                    peerAllowedIPs = etAllowedIPs.text.toString().trim().ifEmpty { server.peerAllowedIPs },
                    peerPersistentKeepalive = etPersistentKeepalive.text.toString().trim().ifEmpty { server.peerPersistentKeepalive },
                    jc = etJc.text.toString().trim().ifEmpty { "0" },
                    jmin = etJmin.text.toString().trim().ifEmpty { "0" },
                    jmax = etJmax.text.toString().trim().ifEmpty { "0" },
                    s1 = etS1.text.toString().trim().ifEmpty { "0" },
                    s2 = etS2.text.toString().trim().ifEmpty { "0" },
                    h1 = etH1.text.toString().trim().ifEmpty { "0" },
                    h2 = etH2.text.toString().trim().ifEmpty { "0" },
                    h3 = etH3.text.toString().trim().ifEmpty { "0" },
                    h4 = etH4.text.toString().trim().ifEmpty { "0" }
                )
                servers[position] = updated
                saveUserServers()
                serverAdapter.notifyItemChanged(position)
                Toast.makeText(this, "Config updated", Toast.LENGTH_SHORT).show()
            }
            .setNeutralButton("Очистить") { _, _ ->
                fun clearAll(v: android.view.View) {
                    when (v) {
                        is android.widget.EditText -> v.setText("")
                        is android.view.ViewGroup -> for (i in 0 until v.childCount) clearAll(v.getChildAt(i))
                    }
                }
                clearAll(view)
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun fillDialogFields(config: ServerInfo) {
        val view = currentDialogView ?: return
        view.findViewById<EditText>(R.id.etName).setText(config.name)
        view.findViewById<EditText>(R.id.etEndpoint).setText(config.peerEndpoint)
        view.findViewById<EditText>(R.id.etPrivateKey).setText(config.interfacePrivateKey)
        view.findViewById<EditText>(R.id.etPublicKey).setText(config.peerPublicKey)
        view.findViewById<EditText>(R.id.etAddress).setText(config.interfaceAddress)
        view.findViewById<EditText>(R.id.etDns).setText(config.interfaceDns)
        view.findViewById<EditText>(R.id.etPresharedKey).setText(config.peerPresharedKey)
        view.findViewById<EditText>(R.id.etAllowedIPs).setText(config.peerAllowedIPs)
        view.findViewById<EditText>(R.id.etPersistentKeepalive).setText(config.peerPersistentKeepalive)
        view.findViewById<EditText>(R.id.etJc).setText(config.jc)
        view.findViewById<EditText>(R.id.etJmin).setText(config.jmin)
        view.findViewById<EditText>(R.id.etJmax).setText(config.jmax)
        view.findViewById<EditText>(R.id.etS1).setText(config.s1)
        view.findViewById<EditText>(R.id.etS2).setText(config.s2)
        view.findViewById<EditText>(R.id.etH1).setText(config.h1)
        view.findViewById<EditText>(R.id.etH2).setText(config.h2)
        view.findViewById<EditText>(R.id.etH3).setText(config.h3)
        view.findViewById<EditText>(R.id.etH4).setText(config.h4)
    }

    private fun showBackupDialog() {
        val backupManager = ServerBackupManager(this)
        AlertDialog.Builder(this)
            .setTitle("Backup")
            .setMessage("Share all configs as JSON file?")
            .setPositiveButton("Share") { _, _ ->
                backupManager.shareBackup()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun showAutoConnectDialog() {
        val storage = AutoConnectStorage(this)
        AlertDialog.Builder(this)
            .setTitle("Auto Connect")
            .setMessage("Automatically connect to first valid server on app start?")
            .setPositiveButton("Enable") { _, _ ->
                storage.setEnabled(true)
                Toast.makeText(this, "Auto connect enabled", Toast.LENGTH_SHORT).show()
            }
            .setNegativeButton("Disable") { _, _ ->
                storage.setEnabled(false)
                Toast.makeText(this, "Auto connect disabled", Toast.LENGTH_SHORT).show()
            }
            .show()
    }

    private fun updateUiState(status: VpnStatus) {
        tvStatus.text = when (status) {
            VpnStatus.DISCONNECTED -> "Status: DISCONNECTED"
            VpnStatus.CONNECTING -> "Status: CONNECTING..."
            VpnStatus.CONNECTED -> "Status: CONNECTED"
            VpnStatus.DISCONNECTING -> "Status: DISCONNECTING..."
            VpnStatus.SWITCHING -> "Status: SWITCHING..."
            VpnStatus.ERROR -> "Status: ERROR"
        }
        val color = when (status) {
            VpnStatus.CONNECTED -> android.graphics.Color.GREEN
            VpnStatus.CONNECTING -> android.graphics.Color.YELLOW
            VpnStatus.SWITCHING -> android.graphics.Color.YELLOW
            VpnStatus.ERROR -> android.graphics.Color.RED
            else -> android.graphics.Color.GRAY
        }
        tvStatus.setTextColor(color)

        // Ненавязчивый тикер: пока идёт подключение, показываем секунды
        // в том же маленьком статусе — чтобы было видно, что процесс живой.
        connectTickHandler.removeCallbacks(connectTicker)
        if (status == VpnStatus.CONNECTING) {
            connectStartMs = System.currentTimeMillis()
            connectTickHandler.post(connectTicker)
        }
    }

    private val connectTickHandler = Handler(Looper.getMainLooper())
    private var connectStartMs = 0L
    private val connectTicker = object : Runnable {
        override fun run() {
            if (VpnManager.globalStatus != VpnStatus.CONNECTING) return
            val secs = (System.currentTimeMillis() - connectStartMs) / 1000
            // Индикатор НЕ сразу: первые 5 секунд — обычный статус,
            // задержка показывается только когда она реально началась.
            if (secs >= 5) {
                tvStatus.text = if (secs < 20) {
                    "Status: CONNECTING… ${secs} сек (ждите)"
                } else {
                    "Status: CONNECTING… ${secs} сек (дольше обычного, подождите)"
                }
            }
            connectTickHandler.postDelayed(this, 1000)
        }
    }
}
