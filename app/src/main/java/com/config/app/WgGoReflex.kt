package com.config.app

import com.wireguard.android.backend.GoBackend

// Phase D: прямой доступ к userspace WireGuard (libwg-go) через приватные
// native-методы GoBackend (JNI биндится по имени класса — Java-видимость
// не мешает). Позволяет передать wg-go СВОЙ fd (socketpair) вместо TUN,
// который библиотека создаёт сама → между приложениями и WG встаёт наш
// форвардер с DNS-фильтром. Единый VPN slot сохраняется: приложения видят
// только интерфейс UnifiedVpnService.
object WgGoReflex {
    private val cls = GoBackend::class.java
    private val mOn = cls.getDeclaredMethod("wgTurnOn", String::class.java, Int::class.java, String::class.java).apply { isAccessible = true }
    private val mOff = cls.getDeclaredMethod("wgTurnOff", Int::class.java).apply { isAccessible = true }
    private val mSock4 = runCatching { cls.getDeclaredMethod("wgGetSocketV4", Int::class.java).apply { isAccessible = true } }.getOrNull()
    private val mSock6 = runCatching { cls.getDeclaredMethod("wgGetSocketV6", Int::class.java).apply { isAccessible = true } }.getOrNull()

    fun turnOn(name: String, fd: Int, cfg: String): Int = mOn.invoke(null, name, fd, cfg) as Int
    fun turnOff(h: Int) { runCatching { mOff.invoke(null, h) } }
    fun socketV4(h: Int): Int = (mSock4?.invoke(null, h) as? Int) ?: -1
    fun socketV6(h: Int): Int = (mSock6?.invoke(null, h) as? Int) ?: -1
}
