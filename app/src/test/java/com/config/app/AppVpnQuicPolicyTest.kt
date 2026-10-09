package com.config.app

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AppVpnQuicPolicyTest {
    @Test fun selectedAppsDropOnlyWithAdBlock() {
        for (apps in listOf(listOf("com.android.chrome"), listOf("com.google.android.googlequicksearchbox"),
            listOf("com.android.chrome", "com.google.android.googlequicksearchbox"))) {
            assertTrue(AppVpnQuicPolicy.shouldDrop("INCLUDE", apps, true))
            assertFalse(AppVpnQuicPolicy.shouldDrop("INCLUDE", apps, false))
            assertFalse(AppVpnQuicPolicy.shouldDrop("GLOBAL", apps, true))
            assertFalse(AppVpnQuicPolicy.shouldDrop("EXCLUDE", apps, true))
        }
    }

    @Test fun youtubeAndMixedScopesKeepNormalQuic() {
        for (apps in listOf(listOf("com.google.android.youtube"),
            listOf("com.android.chrome", "com.google.android.youtube"),
            listOf("com.android.chrome", "other.app"))) {
            assertFalse(AppVpnQuicPolicy.shouldDrop("INCLUDE", apps, true))
        }
    }

    @Test fun emptyScopeNeverDrops() {
        assertFalse(AppVpnQuicPolicy.shouldDrop("INCLUDE", emptyList(), true))
        assertFalse(AppVpnQuicPolicy.shouldDrop("INCLUDE", listOf(" "), true))
    }
}
