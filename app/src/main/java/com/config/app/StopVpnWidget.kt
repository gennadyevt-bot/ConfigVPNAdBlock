package com.config.app

import android.app.PendingIntent
import android.appwidget.AppWidgetManager
import android.appwidget.AppWidgetProvider
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.widget.RemoteViews

class StopVpnWidget : AppWidgetProvider() {

    override fun onUpdate(context: Context, appWidgetManager: AppWidgetManager, appWidgetIds: IntArray) {
        for (appWidgetId in appWidgetIds) {
            updateAppWidget(context, appWidgetManager, appWidgetId)
        }
    }

    override fun onReceive(context: Context, intent: Intent) {
        super.onReceive(context, intent)
        if (intent.action == "com.config.vpnadblock.UPDATE_WIDGET") {
            val appWidgetManager = AppWidgetManager.getInstance(context)
            val componentName = ComponentName(context, StopVpnWidget::class.java)
            val appWidgetIds = appWidgetManager.getAppWidgetIds(componentName)
            onUpdate(context, appWidgetManager, appWidgetIds)
        }
    }

    companion object {
        fun updateWidget(context: Context, status: VpnStatus) {
            val appWidgetManager = AppWidgetManager.getInstance(context)
            val componentName = ComponentName(context, StopVpnWidget::class.java)
            val appWidgetIds = appWidgetManager.getAppWidgetIds(componentName)

            val views = RemoteViews(context.packageName, R.layout.widget_stop_vpn)

            val (stateText, color) = when (status) {
                VpnStatus.CONNECTED -> "ON" to android.graphics.Color.parseColor("#00FF41")
                VpnStatus.CONNECTING -> "..." to android.graphics.Color.parseColor("#FFA500")
                else -> "OFF" to android.graphics.Color.parseColor("#ccffcc")
            }

            views.setTextViewText(R.id.tvWidgetState, stateText)
            views.setTextColor(R.id.tvWidgetState, color)

            for (appWidgetId in appWidgetIds) {
                appWidgetManager.updateAppWidget(appWidgetId, views)
            }
        }
    }

    private fun updateAppWidget(context: Context, appWidgetManager: AppWidgetManager, appWidgetId: Int) {
        val views = RemoteViews(context.packageName, R.layout.widget_stop_vpn)
        appWidgetManager.updateAppWidget(appWidgetId, views)
    }
}
