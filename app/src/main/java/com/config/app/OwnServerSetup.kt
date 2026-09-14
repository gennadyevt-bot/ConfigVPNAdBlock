package com.config.app

import android.content.Context
import android.os.Handler
import android.os.Looper
import android.view.LayoutInflater
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import com.jcraft.jsch.JSch

object OwnServerSetup {

    fun show(context: Context, storage: ServerStorage, onDone: () -> Unit) {
        val view = LayoutInflater.from(context).inflate(R.layout.dialog_own_server, null)
        val etHost = view.findViewById<EditText>(R.id.etHost)
        val etPort = view.findViewById<EditText>(R.id.etPort)
        val etUser = view.findViewById<EditText>(R.id.etUser)
        val etPass = view.findViewById<EditText>(R.id.etPass)
        etPort.setText("22")
        etUser.setText("root")
        AlertDialog.Builder(context)
            .setTitle("Свой сервер")
            .setView(view)
            .setNegativeButton("Отмена", null)
            .setPositiveButton("Настроить") { _, _ ->
                val host = etHost.text.toString().trim()
                val port = etPort.text.toString().toIntOrNull() ?: 22
                val user = etUser.text.toString().trim()
                val pass = etPass.text.toString()
                if (host.isEmpty() || pass.isEmpty()) {
                    Toast.makeText(context, "Введи IP и пароль", Toast.LENGTH_LONG).show()
                    return@setPositiveButton
                }
                Toast.makeText(context, "Настройка сервера, жди 1–2 минуты...", Toast.LENGTH_LONG).show()
                Thread {
                    val result = runSetup(context, host, port, user, pass)
                    Handler(Looper.getMainLooper()).post {
                        result.onSuccess { config ->
                            val info = parseConfigToInfo(config, "Свой сервер", "own")
                            if (info != null) {
                                storage.addServer(info)
                                Toast.makeText(context, "Сервер добавлен в профили", Toast.LENGTH_LONG).show()
                                onDone()
                            } else {
                                Toast.makeText(context, "Конфиг получен, но не распознан", Toast.LENGTH_LONG).show()
                            }
                        }
                        result.onFailure {
                            Toast.makeText(context, "Ошибка: ${it.message}", Toast.LENGTH_LONG).show()
                        }
                    }
                }.start()
            }
            .show()
    }

    fun parseConfigToInfo(config: String, name: String, prefix: String): ServerInfo? {
        fun v(key: String): String {
            val re = Regex("(?m)^" + Regex.escape(key) + "\\s*=\\s*(.+)$")
            return re.find(config)?.groupValues?.get(1)?.trim() ?: ""
        }
        val priv = v("PrivateKey")
        val pub = v("PublicKey")
        if (priv.isEmpty() || pub.isEmpty()) return null
        return ServerInfo(
            id = prefix + "_" + System.currentTimeMillis(),
            name = name,
            flagEmoji = "⭐",
            interfaceAddress = v("Address"),
            interfaceDns = v("DNS").ifEmpty { "1.1.1.1" },
            interfacePrivateKey = priv,
            peerPublicKey = pub,
            peerPresharedKey = v("PresharedKey"),
            peerAllowedIPs = v("AllowedIPs").ifEmpty { "0.0.0.0/0" },
            peerEndpoint = v("Endpoint"),
            peerPersistentKeepalive = v("PersistentKeepalive").ifEmpty { "25" },
            // Missing AWG parameters mean plain WireGuard; preserve explicit values.
            jc = v("Jc").ifEmpty { "0" },
            jmin = v("Jmin").ifEmpty { "0" },
            jmax = v("Jmax").ifEmpty { "0" },
            s1 = v("S1").ifEmpty { "0" },
            s2 = v("S2").ifEmpty { "0" },
            h1 = v("H1").ifEmpty { "0" },
            h2 = v("H2").ifEmpty { "0" },
            h3 = v("H3").ifEmpty { "0" },
            h4 = v("H4").ifEmpty { "0" }
        )
    }

    private fun runSetup(context: Context, host: String, port: Int, user: String, pass: String): Result<String> {
        return try {
            require(host.matches(Regex("[A-Za-z0-9.-]+"))) { "Укажите IPv4 или DNS-имя сервера без пробелов и команд" }
            require(port in 1..65535) { "Неверный порт SSH" }
            val jsch = JSch()
            val knownHosts = java.io.File(context.filesDir, "ssh_known_hosts")
            if (!knownHosts.exists()) knownHosts.createNewFile()
            jsch.setKnownHosts(knownHosts.absolutePath)
            val session = jsch.getSession(user, host, port)
            session.setPassword(pass)
            session.userInfo = object : com.jcraft.jsch.UserInfo {
                override fun getPassword(): String? = null
                override fun getPassphrase(): String? = null
                override fun promptPassword(message: String?): Boolean = false
                override fun promptPassphrase(message: String?): Boolean = false
                override fun showMessage(message: String?) {}
                override fun promptYesNo(message: String?): Boolean {
                    val result = java.util.concurrent.atomic.AtomicBoolean(false)
                    val latch = java.util.concurrent.CountDownLatch(1)
                    Handler(Looper.getMainLooper()).post {
                        val activity = context as? android.app.Activity
                        if (activity == null || activity.isFinishing || activity.isDestroyed) {
                            latch.countDown()
                        } else {
                            AlertDialog.Builder(context)
                                .setTitle("Проверка SSH-сервера")
                                .setMessage("Сверьте отпечаток с панелью вашего сервера. Подтверждайте только известный вам сервер.\n\n" + message)
                                .setPositiveButton("Доверять") { _, _ -> result.set(true); latch.countDown() }
                                .setNegativeButton("Отмена") { _, _ -> latch.countDown() }
                                .setOnCancelListener { latch.countDown() }
                                .show()
                        }
                    }
                    return latch.await(120, java.util.concurrent.TimeUnit.SECONDS) && result.get()
                }
            }
            val cfg = java.util.Properties()
            cfg["StrictHostKeyChecking"] = "ask"
            session.setConfig(cfg)
            session.timeout = 20000
            session.connect()
            val channel = session.openChannel("exec") as com.jcraft.jsch.ChannelExec
            channel.setCommand(SETUP_SCRIPT.replace("__HOST__", host))
            channel.inputStream = null
            channel.setErrStream(System.err)
            val input = channel.inputStream
            channel.connect(30000)
            val out = String(input.readBytes(), Charsets.UTF_8)
            channel.disconnect()
            session.disconnect()
            val s = out.indexOf("===CONFIG-START===")
            val e = out.indexOf("===CONFIG-END===")
            if (s < 0 || e <= s) {
                Result.failure(Exception("Сервер не вернул конфиг. Проверь IP, пароль и порт SSH (22 может блокироваться — попробуй 2222 или 443)."))
            } else {
                Result.success(out.substring(s + 18, e).trim())
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    private const val SETUP_SCRIPT = "apt update && apt install -y wireguard-tools && cd /etc/wireguard && umask 077 && wg genkey | tee server.key | wg pubkey > server.pub && wg genkey | tee client.key | wg pubkey > client.pub && SPRIV=\$(cat server.key) && CPRIV=\$(cat client.key) && SPUB=\$(cat server.pub) && CPUB=\$(cat client.pub) && IFACE=\$(ip route show default | awk '{print \$5}' | head -n1) && printf '[Interface]\\nPrivateKey = %s\\nAddress = 10.66.66.1/24\\nListenPort = 51820\\nPostUp = iptables -A FORWARD -i %%i -j ACCEPT; iptables -A FORWARD -o %%i -j ACCEPT; iptables -t nat -A POSTROUTING -o %s -j MASQUERADE\\nPostDown = iptables -D FORWARD -i %%i -j ACCEPT; iptables -D FORWARD -o %%i -j ACCEPT; iptables -t nat -D POSTROUTING -o %s -j MASQUERADE\\n\\n[Peer]\\nPublicKey = %s\\nAllowedIPs = 10.66.66.2/32\\n' \"\$SPRIV\" \"\$IFACE\" \"\$IFACE\" \"\$CPUB\" > wg0.conf && chmod 600 wg0.conf && printf 'net.ipv4.ip_forward=1\\n' >> /etc/sysctl.conf && sysctl -w net.ipv4.ip_forward=1 && systemctl enable --now wg-quick@wg0 && echo ===CONFIG-START=== && printf '[Interface]\\nPrivateKey = %s\\nAddress = 10.66.66.2/32\\nDNS = 1.1.1.1\\n\\n[Peer]\\nPublicKey = %s\\nAllowedIPs = 0.0.0.0/0\\nEndpoint = __HOST__:51820\\nPersistentKeepalive = 25\\n' \"\$CPRIV\" \"\$SPUB\" && echo ===CONFIG-END==="
}
