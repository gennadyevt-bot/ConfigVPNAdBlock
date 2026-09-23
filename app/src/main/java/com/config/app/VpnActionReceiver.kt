package com.config.app

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

class VpnActionReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == "com.config.vpnadblock.CONNECT_VPN") {
            val domain = intent.getStringExtra("domain") ?: ""
            android.util.Log.d("VpnActionReceiver", "Connect VPN for domain: $domain")

            val vpnManager = VpnManager.getInstance(context)
            val servers = EmbeddedServers.all(context)
            val validServer = servers.firstOrNull {
                it.interfacePrivateKey.isNotEmpty() &&
                it.peerPublicKey.isNotEmpty() &&
                it.peerEndpoint.isNotEmpty()
            }
            validServer?.let {
                CoroutineScope(Dispatchers.IO).launch {
                    try {
                        vpnManager.connect(it)
                    } catch (e: Exception) {
                        android.util.Log.e("VpnActionReceiver", "Connect failed", e)
                    }
                }
            }
        }
    }
}