package com.config.app

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class WgConfigParserTest {

    private val wgConf = """
        [Interface]
        PrivateKey = abcdefgh
        Address = 10.66.67.2/32
        DNS = 1.1.1.1
        MTU = 1280

        [Peer]
        PublicKey = xyzpubkey
        Endpoint = 193.233.211.41:51821
        AllowedIPs = 0.0.0.0/0
        PersistentKeepalive = 25
    """.trimIndent()

    private val awgConf = wgConf + "\nJc = 3\nJmin = 10\nJmax = 50\nS1 = 0\nS2 = 0\nH1 = 1\nH2 = 2\nH3 = 3\nH4 = 4"

    @Test
    fun testA_mtuParsed() {
        val s = WgConfigParser.parse(wgConf)!!
        assertEquals("1280", s.interfaceMtu)
    }

    @Test
    fun testB_awgParamsAfterPeer() {
        val s = WgConfigParser.parse(awgConf)!!
        assertEquals("3", s.jc)
        assertEquals("10", s.jmin)
        assertEquals("50", s.jmax)
        assertEquals("0", s.s1)
        assertEquals("0", s.s2)
        assertEquals("1", s.h1)
        assertEquals("2", s.h2)
        assertEquals("3", s.h3)
        assertEquals("4", s.h4)
    }

    @Test
    fun testC_plainWgStaysPlain() {
        val s = WgConfigParser.parse(wgConf)!!
        assertTrue("jc must be empty or 0 for plain WG", s.jc.isEmpty() || s.jc == "0")
        assertTrue("s1 must be empty for plain WG", s.s1.isEmpty() || s.s1 == "0")
    }

    @Test
    fun testD_oldJsonWithoutMtuLoads() {
        val json = JSONObject("""{"id":"x1","name":"Old","interfaceAddress":"10.66.67.2/32","interfacePrivateKey":"k","peerPublicKey":"p","peerEndpoint":"e:1"}""")
        val s = ServerStorage.jsonToServer(json)
        assertNotNull(s)
        assertEquals("", s!!.interfaceMtu)
    }
}
