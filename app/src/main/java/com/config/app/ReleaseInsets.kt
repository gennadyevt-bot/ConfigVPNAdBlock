package com.config.app

import android.app.Activity
import android.view.View
import android.view.ViewGroup
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat

/** Retain the existing content spacing when Android 15+ enforces edge-to-edge. */
fun Activity.applyReleaseInsets() {
    val root = findViewById<ViewGroup>(android.R.id.content).getChildAt(0) ?: return
    val left = root.paddingLeft
    val top = root.paddingTop
    val right = root.paddingRight
    val bottom = root.paddingBottom
    root.fitsSystemWindows = false
    ViewCompat.setOnApplyWindowInsetsListener(root) { view: View, insets ->
        val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout())
        val ime = insets.getInsets(WindowInsetsCompat.Type.ime())
        view.setPadding(left + bars.left, top + bars.top, right + bars.right, bottom + maxOf(bars.bottom, ime.bottom))
        WindowInsetsCompat.CONSUMED
    }
    ViewCompat.requestApplyInsets(root)
}
