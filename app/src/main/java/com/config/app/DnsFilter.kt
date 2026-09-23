package com.config.app

import kotlin.concurrent.thread

// Phase D: DNS/hostname фильтр. Разбирает IPv4/UDP/53 пакеты из TUN,
// матчит домены против blocklist (суффикс-совпадение). Заблокированному
// запросу возвращается NXDOMAIN синтезированный ответ.
// Ошибки парсинга = пакет пропускается (fail-open).
object DnsFilter {
    private val blocked = HashSet<String>()
    @Volatile var loaded = false
    @Volatile var rules = 0

    fun load(context: android.content.Context) {
        if (loaded) return
        thread(name = "adblock-load") {
            try {
                val set = HashSet<String>(70000)
                context.assets.open("blocklist.txt").bufferedReader().useLines { lines ->
                    lines.forEach { raw ->
                        var l = raw.trim().lowercase()
                        if (l.isEmpty() || l.startsWith("#") || l.startsWith("!")) return@forEach
                        if (l.startsWith("0.0.0.0 ") || l.startsWith("127.0.0.1 ")) {
                            l = l.substring(l.indexOf(' ') + 1).trim()
                        }
                        if (l.startsWith("||")) {
                            l = l.removePrefix("||").substringBefore('^').substringBefore('*').substringBefore('/')
                        }
                        l = l.removePrefix("www.")
                        if (l.isNotEmpty() && !l.contains(" ") && l.contains(".")) set.add(l)
                    }
                }
                synchronized(blocked) { blocked.clear(); blocked.addAll(set) }
                rules = set.size
                loaded = true
                AdBlockLog.add("ADBLOCK: START rules=" + set.size)
            } catch (e: Exception) {
                AdBlockLog.add("ADBLOCK: ERROR load " + (e.message ?: e.javaClass.simpleName))
            }
        }
    }

    fun isBlocked(domain: String): Boolean {
        var d = domain.lowercase().removeSuffix(".")
        val set = synchronized(blocked) { blocked }
        while (d.contains(".")) {
            if (d in set) return true
            d = d.substringAfter(".")
        }
        return false
    }

    /** null = пропустить; иначе ByteArray с NXDOMAIN-ответом для отправки приложению */
    fun tryBlock(pkt: ByteArray, n: Int): ByteArray? {
        if (!loaded || n < 28) return null
        if ((pkt[0].toInt() ushr 4) != 4) return null // Phase D: IPv4 UDP/53
        val ihl = (pkt[0].toInt() and 0xF) * 4
        if (n < ihl + 8 + 12 || pkt[9].toInt() != 17) return null
        val dport = ((pkt[ihl + 2].toInt() and 0xFF) shl 8) or (pkt[ihl + 3].toInt() and 0xFF)
        if (dport != 53) return null
        val dnsOff = ihl + 8
        val flags = ((pkt[dnsOff].toInt() and 0xFF) shl 8) or (pkt[dnsOff + 1].toInt() and 0xFF)
        if (flags and 0x8000 != 0) return null // это ответ — не трогаем
        val sb = StringBuilder()
        var i = dnsOff + 12
        var guard = 0
        while (i < n && guard++ < 40) {
            val len = pkt[i].toInt() and 0xFF
            if (len == 0) break
            if (len and 0xC0 != 0) return null // сжатие в запросе — пропускаем
            if (i + 1 + len > n) return null
            if (sb.isNotEmpty()) sb.append('.')
            for (k in 1..len) sb.append((pkt[i + k].toInt() and 0xFF).toChar())
            i += len + 1
        }
        val domain = sb.toString()
        if (domain.isEmpty() || !isBlocked(domain)) return null
        AdBlockLog.add("DNS: BLOCK domain=$domain")
        return buildNxDomain(pkt, n, ihl, dnsOff)
    }

    private fun buildNxDomain(src: ByteArray, n: Int, ihl: Int, dnsOff: Int): ByteArray {
        val r = src.copyOf(n)
        // swap IP src/dst (байты 12..19)
        val srcIp = r.copyOfRange(12, 16)
        for (k in 0..3) r[12 + k] = r[16 + k]
        for (k in 0..3) r[16 + k] = srcIp[k]
        // swap UDP ports
        val sp = r[ihl]; val sp2 = r[ihl + 1]
        r[ihl] = r[ihl + 2]; r[ihl + 1] = r[ihl + 3]
        r[ihl + 2] = sp; r[ihl + 3] = sp2
        // DNS: QR=1, RCODE=3 (NXDOMAIN), AN=NS=AR=0
        r[dnsOff] = 0x81.toByte(); r[dnsOff + 1] = 0x83.toByte()
        for (k in 4..9) r[dnsOff + k] = 0
        // UDP checksum = 0 (допустимо в IPv4)
        r[ihl + 6] = 0; r[ihl + 7] = 0
        // IP checksum пересчитать
        r[10] = 0; r[11] = 0
        val c = ipChecksum(r, ihl)
        r[10] = (c ushr 8).toByte(); r[11] = (c and 0xFF).toByte()
        return r
    }

    private fun ipChecksum(b: ByteArray, len: Int): Int {
        var sum = 0
        var i = 0
        while (i < len) {
            var w = (b[i].toInt() and 0xFF) shl 8
            if (i + 1 < len) w = w or (b[i + 1].toInt() and 0xFF)
            sum += w
            i += 2
        }
        sum = (sum ushr 16) + (sum and 0xFFFF)
        sum += sum ushr 16
        return sum.inv() and 0xFFFF
    }
}
