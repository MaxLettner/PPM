package dev.peerpass

import android.annotation.SuppressLint
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.PowerManager
import android.provider.Settings

/** Shortcuts into system settings that keep background sync alive on Doke OS. */
object DeviceSettings {
    fun ignoringBatteryOptimizations(c: Context) =
        c.getSystemService(PowerManager::class.java).isIgnoringBatteryOptimizations(c.packageName)

    @SuppressLint("BatteryLife") // a password manager's background sync is the documented use case
    fun requestIgnoreBatteryOptimizations(c: Context) {
        c.startActivity(Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, Uri.parse("package:${c.packageName}")).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    }

    /**
     * Auto-start manager. Doke OS (Blackview) has no documented intent for it, so this tries
     * the component names of common Android skins and otherwise opens the app's system
     * settings page (unverified on Doke OS; see README for the manual path).
     */
    private val autoStartCandidates = listOf(
        ComponentName("com.transsion.phonemaster", "com.cyin.himgr.autostart.AutoStartActivity"),
        ComponentName("com.miui.securitycenter", "com.miui.permcenter.autostart.AutoStartManagementActivity"),
        ComponentName("com.coloros.safecenter", "com.coloros.safecenter.permission.startup.StartupAppListActivity"),
    )

    fun openAutoStart(c: Context) {
        for (cn in autoStartCandidates) {
            val i = Intent().setComponent(cn).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            if (i.resolveActivity(c.packageManager) != null && runCatching { c.startActivity(i) }.isSuccess) return
        }
        openAppDetails(c)
    }

    fun openAppDetails(c: Context) {
        c.startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:${c.packageName}")).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    }

    fun openAutofillSettings(c: Context) {
        c.startActivity(Intent(Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE, Uri.parse("package:${c.packageName}")).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    }
}
