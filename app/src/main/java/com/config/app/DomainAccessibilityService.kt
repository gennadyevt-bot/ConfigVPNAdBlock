package com.config.app

import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.AccessibilityServiceInfo
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

class DomainAccessibilityService : AccessibilityService() {

    private var vpnManager: VpnManager? = null
    private var domainStorage: DomainVpnStorage? = null
    private val toastHandler = Handler(Looper.getMainLooper())
    private var lastToastTime = 0L
    private val previousUrlDetections = HashMap<String, Long>()

    companion object {
        private const val TAG = "DomainVPN"
        private const val COOLDOWN_MS = 2000L
        private const val TOAST_COOLDOWN_MS = 2000L
        private const val NOTIFICATION_ID_PREPARE = 3001

        private val URL_REGEX = Regex("""https?://[^\s<>"{}|\\^`\[\]]+""")
        private val DOMAIN_REGEX = Regex("""(?:https?://)?(?:www\.)?([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}(?:\.[-a-zA-Z0-9]+)*)""")

        // === Browser configs: packageName -> addressBarId ===
        private val BROWSER_CONFIGS = listOf(
            BrowserConfig("com.android.chrome", "com.android.chrome:id/url_bar"),
            BrowserConfig("com.chrome.beta", "com.chrome.beta:id/url_bar"),
            BrowserConfig("com.chrome.dev", "com.chrome.dev:id/url_bar"),
            BrowserConfig("com.chrome.canary", "com.chrome.canary:id/url_bar"),
            BrowserConfig("org.mozilla.firefox", "org.mozilla.firefox:id/mozac_browser_toolbar_url_view"),
            BrowserConfig("org.mozilla.firefox", "org.mozilla.firefox:id/url_bar_title"), // fallback
            BrowserConfig("com.opera.browser", "com.opera.browser:id/url_field"),
            BrowserConfig("com.opera.mini.native", "com.opera.mini.native:id/url_field"),
            BrowserConfig("com.opera.mini.native.beta", "com.opera.mini.native.beta:id/url_field"),
            BrowserConfig("com.duckduckgo.mobile.android", "com.duckduckgo.mobile.android:id/omnibarTextInput"),
            BrowserConfig("com.microsoft.emmx", "com.microsoft.emmx:id/url_bar"),
            BrowserConfig("com.microsoft.emmx.beta", "com.microsoft.emmx.beta:id/url_bar"),
            BrowserConfig("com.sec.android.app.sbrowser", "com.sec.android.app.sbrowser:id/location_bar_edit_text"),
            BrowserConfig("com.sec.android.app.sbrowser.beta", "com.sec.android.app.sbrowser.beta:id/location_bar_edit_text"),
            BrowserConfig("com.brave.browser", "com.brave.browser:id/url_bar"),
            BrowserConfig("com.kiwibrowser.browser", "com.kiwibrowser.browser:id/url_bar"),
            BrowserConfig("com.vivaldi.browser", "com.vivaldi.browser:id/url_bar"),
            BrowserConfig("com.yandex.browser", "com.yandex.browser:id/omnibar_text"),
        )

        // Telegram packages
        private val TELEGRAM_PACKAGES = setOf(
            "org.telegram.messenger",
            "org.telegram.messenger.web",
            "org.telegram.plus",
            "org.thunderdog.challegram", // Telegram X
            "nekogram.messenger",
            "com.exteragram.messenger"
        )
    }

    data class BrowserConfig(val packageName: String, val addressBarId: String)

    override fun onServiceConnected() {
        super.onServiceConnected()
        vpnManager = VpnManager.getInstance(this)
        domainStorage = DomainVpnStorage(this)

        // Настраиваем сервис info программно для максимальной совместимости
        val info = serviceInfo
        info.eventTypes = AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED or
                          AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED or
                          AccessibilityEvent.TYPE_WINDOWS_CHANGED or
                          AccessibilityEvent.TYPE_VIEW_CLICKED or
                          AccessibilityEvent.TYPE_VIEW_LONG_CLICKED
        info.feedbackType = AccessibilityServiceInfo.FEEDBACK_VISUAL
        info.notificationTimeout = 300
        info.flags = AccessibilityServiceInfo.FLAG_REPORT_VIEW_IDS or
                     AccessibilityServiceInfo.FLAG_RETRIEVE_INTERACTIVE_WINDOWS or
                     AccessibilityServiceInfo.FLAG_INCLUDE_NOT_IMPORTANT_VIEWS
        // Не фильтруем по packageNames — ловим ВСЕ события
        info.packageNames = null
        serviceInfo = info

        showToast("Domain VPN: сервис запущен")
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent) {
        val storage = domainStorage ?: return
        if (!storage.isEnabled()) return

        val domains = storage.getDomains()
        if (domains.isEmpty()) return

        val pkg = event.packageName?.toString() ?: ""
        val eventType = event.eventType
        val eventName = eventTypeToName(eventType)

        // === СТРАТЕГИЯ 1: Браузер — ищем URL по ID адресной строки ===
        val browserConfig = findBrowserConfig(pkg)
        if (browserConfig != null) {
            val url = captureBrowserUrl(browserConfig)
            if (url != null) {
                processUrl(url, domains, "browser.id")
                return
            }
        }

        // === СТРАТЕГИЯ 2: Telegram — ищем URL в окне ===
        if (isTelegramPackage(pkg)) {

            // Пробуем получить URL из window.title
            val windows = windows
            for (window in windows) {
                val title = window.title?.toString() ?: ""
                if (title.isNotEmpty() && !title.contains("Telegram") && !title.contains("Chat") && !title.contains("Channel")) {
                    val url = extractUrl(title)
                    if (url.isNotEmpty()) {
                        processUrl(url, domains, "telegram.title")
                        return
                    }
                }
            }

            // Пробуем извлечь из event.text
            val eventText = event.text?.joinToString(" ") ?: ""
            if (eventText.isNotEmpty()) {
                val url = extractUrl(eventText)
                if (url.isNotEmpty()) {
                    processUrl(url, domains, "telegram.text")
                    return
                }
            }

            // Пробуем из contentDescription
            val contentDesc = event.contentDescription?.toString() ?: ""
            if (contentDesc.isNotEmpty()) {
                val url = extractUrl(contentDesc)
                if (url.isNotEmpty()) {
                    processUrl(url, domains, "telegram.desc")
                    return
                }
            }

            // Пробуем из event.source
            val source = event.source
            if (source != null) {
                val url = extractUrlFromNode(source)
                source.recycle()
                if (url.isNotEmpty()) {
                    processUrl(url, domains, "telegram.source")
                    return
                }
            }

            // Глубокое сканирование всего окна Telegram
            val root = rootInActiveWindow
            if (root != null) {
                val url = findUrlDeep(root)
                root.recycle()
                if (url.isNotEmpty()) {
                    processUrl(url, domains, "telegram.deep")
                    return
                }
            }
        }

        // === СТРАТЕГИЯ 3: packageName совпадает с доменом ===
        val matchedByPkg = domains.firstOrNull { domain ->
            val base = domain.removePrefix("www.").split(".")[0]
            pkg.contains(base, ignoreCase = true)
        }
        if (matchedByPkg != null) {
            showToast("VPN: $matchedByPkg")
            triggerVpnConnect(matchedByPkg)
        }
    }

    override fun onInterrupt() {}

    // ==================== BROWSER URL CAPTURE ====================

    private fun findBrowserConfig(pkg: String): BrowserConfig? {
        return BROWSER_CONFIGS.firstOrNull { it.packageName == pkg }
    }

    private fun captureBrowserUrl(config: BrowserConfig): String? {
        val root = rootInActiveWindow ?: return null
        val nodes = root.findAccessibilityNodeInfosByViewId(config.addressBarId)
        root.recycle()

        if (nodes.isNullOrEmpty()) {
            return null
        }

        val node = nodes[0]
        val url = node.text?.toString()
        node.recycle()

        if (url.isNullOrEmpty() || url == "Search or type URL") {
            return null
        }

        // Chrome иногда показывает URL без https://
        return if (url.startsWith("http")) url else "https://$url"
    }

    // ==================== URL EXTRACTION ====================

    private fun extractUrl(text: String): String {
        if (text.isEmpty()) return ""
        val match = URL_REGEX.find(text)
        if (match != null) return match.value
        val domainMatch = DOMAIN_REGEX.find(text)
        if (domainMatch != null) return "https://${domainMatch.groupValues[1]}"
        return ""
    }

    private fun extractUrlFromNode(node: AccessibilityNodeInfo): String {
        val sources = listOf(
            node.text?.toString() ?: "",
            node.contentDescription?.toString() ?: "",
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) node.hintText?.toString() ?: "" else "",
            node.viewIdResourceName ?: ""
        )
        for (src in sources) {
            if (src.isNotEmpty()) {
                val extracted = extractUrl(src)
                if (extracted.isNotEmpty()) return extracted
            }
        }
        return ""
    }

    private fun findUrlDeep(root: AccessibilityNodeInfo): String {
        var count = 0
        val queue = java.util.ArrayDeque<Pair<AccessibilityNodeInfo, Int>>()
        queue.add(Pair(root, 0))
        val visited = java.util.HashSet<Int>()

        while (queue.isNotEmpty() && count < 1000) {
            val (node, depth) = queue.poll()
            count++
            if (depth > 12) continue

            val nodeId = System.identityHashCode(node)
            if (visited.contains(nodeId)) continue
            visited.add(nodeId)

            val text = node.text?.toString() ?: ""
            val desc = node.contentDescription?.toString() ?: ""
            val hint = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) node.hintText?.toString() ?: "" else ""

            for (src in listOf(text, desc, hint)) {
                if (src.isNotEmpty() && src.length > 4) {
                    val extracted = extractUrl(src)
                    if (extracted.isNotEmpty()) {
                        return extracted
                    }
                }
            }

            for (i in 0 until node.childCount) {
                val child = node.getChild(i)
                if (child != null) queue.add(Pair(child, depth + 1))
            }
        }
        return ""
    }

    private fun extractHost(url: String): String {
        return url.removePrefix("https://").removePrefix("http://").removePrefix("www.")
            .split("/")[0].split(":")[0]
    }

    // ==================== PROCESSING ====================

    private fun processUrl(url: String, domains: Set<String>, source: String) {
        val host = extractHost(url)

        // Дедупликация: один и тот же URL не обрабатываем чаще 2 сек
        val detectionId = "$source:$url"
        val now = System.currentTimeMillis()
        val lastTime = previousUrlDetections[detectionId] ?: 0L
        if (now - lastTime < COOLDOWN_MS) {
            return
        }
        previousUrlDetections[detectionId] = now

        val matched = domains.firstOrNull { domain ->
            url.contains(domain, ignoreCase = true) ||
            host.equals(domain, ignoreCase = true) ||
            host.endsWith(".$domain", ignoreCase = true)
        }

        if (matched != null) {
            showToast("VPN: $matched")
            triggerVpnConnect(matched)
        } else {
        }
    }

    // ==================== VPN TRIGGER ====================

    private fun triggerVpnConnect(domain: String) {
        if (VpnService.prepare(this) != null) {
            android.util.Log.w(TAG, "VPN not prepared")
            showPrepareNotification(domain)
            return
        }
        val status = VpnManager.globalStatus
        if (status == VpnStatus.DISCONNECTED || status == VpnStatus.ERROR) {
            autoConnectVpn(domain)
        } else {
        }
    }

    private fun autoConnectVpn(domain: String) {
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val servers = EmbeddedServers.all(this@DomainAccessibilityService)
                val valid = servers.firstOrNull {
                    it.interfacePrivateKey.isNotEmpty() &&
                    it.peerPublicKey.isNotEmpty() &&
                    it.peerEndpoint.isNotEmpty()
                }
                if (valid != null) {
                    vpnManager?.connect(valid)
                    showConnectedNotification(domain)
                } else {
                    showToast("Нет валидных серверов")
                }
            } catch (e: Exception) {
                android.util.Log.e(TAG, "Auto-connect failed", e)
                showToast("Ошибка: ${e.message}")
            }
        }
    }

    // ==================== UTILS ====================

    private fun isTelegramPackage(pkg: String): Boolean {
        return TELEGRAM_PACKAGES.any { pkg.contains(it, ignoreCase = true) }
    }

    private fun eventTypeToName(type: Int): String {
        return when (type) {
            AccessibilityEvent.TYPE_VIEW_CLICKED -> "CLICK"
            AccessibilityEvent.TYPE_VIEW_LONG_CLICKED -> "LONG_CLICK"
            AccessibilityEvent.TYPE_VIEW_SELECTED -> "SELECTED"
            AccessibilityEvent.TYPE_VIEW_FOCUSED -> "FOCUSED"
            AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED -> "TEXT_CHANGED"
            AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED -> "WINDOW_STATE"
            AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED -> "CONTENT_CHANGED"
            AccessibilityEvent.TYPE_WINDOWS_CHANGED -> "WINDOWS_CHANGED"
            AccessibilityEvent.TYPE_VIEW_SCROLLED -> "SCROLLED"
            else -> "OTHER($type)"
        }
    }

    // ==================== NOTIFICATIONS ====================

    private fun showPrepareNotification(domain: String) {
        val channelId = "domain_vpn_prepare"
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(channelId, "Domain VPN", NotificationManager.IMPORTANCE_HIGH)
            getSystemService(NotificationManager::class.java)?.createNotificationChannel(channel)
        }
        val intent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra("auto_connect_domain", domain)
        }
        val pendingIntent = PendingIntent.getActivity(
            this, 0, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val notification = NotificationCompat.Builder(this, channelId)
            .setContentTitle("Разрешите VPN для $domain")
            .setContentText("Нажмите, чтобы открыть приложение")
            .setSmallIcon(android.R.drawable.ic_menu_mylocation)
            .setContentIntent(pendingIntent)
            .setAutoCancel(true)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .build()
        getSystemService(NotificationManager::class.java)?.notify(NOTIFICATION_ID_PREPARE, notification)
    }

    private fun showConnectedNotification(domain: String) {
        val channelId = "domain_vpn_channel"
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(channelId, "Domain VPN", NotificationManager.IMPORTANCE_DEFAULT)
            getSystemService(NotificationManager::class.java)?.createNotificationChannel(channel)
        }
        val notification = NotificationCompat.Builder(this, channelId)
            .setContentTitle("VPN активирован")
            .setContentText("Для $domain")
            .setSmallIcon(android.R.drawable.ic_menu_mylocation)
            .setAutoCancel(true)
            .build()
        getSystemService(NotificationManager::class.java)?.notify(2002, notification)
    }

    private fun showToast(msg: String) {
        val now = System.currentTimeMillis()
        if (now - lastToastTime < TOAST_COOLDOWN_MS) return
        lastToastTime = now
        toastHandler.post {
            android.widget.Toast.makeText(this, msg, android.widget.Toast.LENGTH_SHORT).show()
        }
    }
}
