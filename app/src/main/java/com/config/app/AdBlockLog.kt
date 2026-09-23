package com.config.app

// Phase D: кольцевой журнал AdBlock (логи также идут в logcat с тегом ADBLOCK).
object AdBlockLog {
    private const val MAX = 200
    private val buf = ArrayDeque<String>()

    @Synchronized
    fun add(s: String) {
        buf.addLast(s)
        while (buf.size > MAX) buf.removeFirst()
        android.util.Log.d("ADBLOCK", s)
    }

    @Synchronized
    fun snapshot(): List<String> = buf.toList()
}
