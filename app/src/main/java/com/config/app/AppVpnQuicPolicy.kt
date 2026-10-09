package com.config.app

internal object AppVpnQuicPolicy {
    fun shouldDrop(mode: String, allowed: List<String>, adBlockEnabled: Boolean): Boolean =
        adBlockEnabled && mode == "INCLUDE" && allowed.isNotEmpty() &&
            allowed.all {
                it == "com.android.chrome" || it == "com.google.android.googlequicksearchbox"
            }
}
