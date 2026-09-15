package com.config.app

data class ServerInfo(
    val id: String,
    val name: String,
    val country: String = "",
    val flagEmoji: String = "",
    val interfaceAddress: String = "",
    val interfaceDns: String = "1.1.1.1, 8.8.8.8",
    val interfaceMtu: String = "",
    val interfacePrivateKey: String = "",
    val peerPublicKey: String = "",
    val peerPresharedKey: String = "",
    val peerAllowedIPs: String = "0.0.0.0/0",
    val peerEndpoint: String = "",
    val peerPersistentKeepalive: String = "25",
    val jc: String = "",
    val jmin: String = "",
    val jmax: String = "",
    val s1: String = "",
    val s2: String = "",
    val h1: String = "",
    val h2: String = "",
    val h3: String = "",
    val h4: String = "",
    val includedApps: List<String> = emptyList(),
    val excludedApps: List<String> = emptyList()
)
