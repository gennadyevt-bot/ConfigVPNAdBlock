package com.config.app

import org.junit.Assert.*
import org.junit.Test

class WgConfigParserTest {
    // Synthetic placeholders, never a deployable VPN credential.
    private val plain = """
        [Interface]
        PrivateKey = synthetic-private==
        Address = 10.0.0.2/32, fd00::2/128
        DNS = 1.1.1.1
        [Peer]
        PublicKey = synthetic-public==
        Endpoint = [2001:db8::1]:51820
        AllowedIPs = 0.0.0.0/0, ::/0
    """.trimIndent()

    @Test fun plainWireGuardDoesNotEnableAmneziaJunk() {
        val server = requireNotNull(WgConfigParser.parse(plain))
        assertEquals("0", server.jc)
        assertEquals("synthetic-private==", server.interfacePrivateKey)
        assertEquals("[2001:db8::1]:51820", server.peerEndpoint)
        assertEquals("0.0.0.0/0, ::/0", server.peerAllowedIPs)
    }

    @Test fun amneziaParametersSurviveImport() {
        val server = requireNotNull(WgConfigParser.parse(plain.replace("[Peer]", "Jc = 4\nJmin = 40\nJmax = 120\nH1 = 123456\n[Peer]")))
        assertEquals("4", server.jc)
        assertEquals("40", server.jmin)
        assertEquals("120", server.jmax)
        assertEquals("123456", server.h1)
    }

    @Test fun incompleteProfileIsRejected() {
        assertNull(WgConfigParser.parse(""))
        assertNull(WgConfigParser.parse(plain.replace("PublicKey = synthetic-public==", "")))
        assertNull(WgConfigParser.parse(plain.replace("Endpoint = [2001:db8::1]:51820", "")))
    }
}
