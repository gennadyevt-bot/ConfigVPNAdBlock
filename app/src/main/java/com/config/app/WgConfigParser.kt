package com.config.app

object WgConfigParser {

    fun parse(configText: String): ServerInfo? {
        val lines = configText.lines().map { it.trim() }.filter { it.isNotEmpty() }
        if (lines.isEmpty()) return null

        var name = "QR Config"
        var address = ""
        var dns = "1.1.1.1, 8.8.8.8"
        var mtu = ""
        var privateKey = ""
        var publicKey = ""
        var presharedKey = ""
        var endpoint = ""
        var allowedIPs = "0.0.0.0/0"
        var persistentKeepalive = "25"
        var jc = ""
        var jmin = ""
        var jmax = ""
        var s1 = ""
        var s2 = ""
        var h1 = ""
        var h2 = ""
        var h3 = ""
        var h4 = ""

        var inInterface = false
        var inPeer = false

        for (line in lines) {
            when {
                line.equals("[Interface]", ignoreCase = true) -> {
                    inInterface = true
                    inPeer = false
                }
                line.equals("[Peer]", ignoreCase = true) -> {
                    inInterface = false
                    inPeer = true
                }
                line.startsWith("#") || line.startsWith(";") -> continue
                // AWG-параметры обфускации встречаются в обеих секциях — принимаем из любой
                inInterface || inPeer -> {
                    val (key, value) = parseKeyValue(line) ?: continue
                    when (key.lowercase()) {
                        "address" -> if (inInterface) address = value
                        "dns" -> if (inInterface) dns = value.substringBefore(",").trim()
                        "mtu" -> if (inInterface) mtu = value
                        "privatekey" -> if (inInterface) privateKey = value
                        "publickey" -> if (inPeer) publicKey = value
                        "presharedkey" -> if (inPeer) presharedKey = value
                        "endpoint" -> if (inPeer) endpoint = value
                        "allowedips" -> if (inPeer) allowedIPs = value
                        "persistentkeepalive" -> if (inPeer) persistentKeepalive = value
                        "jc" -> jc = value
                        "jmin" -> jmin = value
                        "jmax" -> jmax = value
                        "s1" -> s1 = value
                        "s2" -> s2 = value
                        "h1" -> h1 = value
                        "h2" -> h2 = value
                        "h3" -> h3 = value
                        "h4" -> h4 = value
                    }
                }
            }
        }

        if (privateKey.isEmpty() || publicKey.isEmpty() || endpoint.isEmpty()) {
            return null
        }

        return ServerInfo(
            id = "qr_${System.currentTimeMillis()}",
            name = name,
            interfaceAddress = address,
            interfaceDns = dns,
            interfaceMtu = mtu,
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
    }

    private fun parseKeyValue(line: String): Pair<String, String>? {
        val eqIndex = line.indexOf('=')
        if (eqIndex == -1) return null
        val key = line.substring(0, eqIndex).trim()
        val value = line.substring(eqIndex + 1).trim()
        if (key.isEmpty()) return null
        return key to value
    }
}
