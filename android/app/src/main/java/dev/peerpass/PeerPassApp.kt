package dev.peerpass

import android.app.Application
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import java.io.File
import uniffi.peerpass_ffi.PeerPass

class PeerPassApp : Application() {
    lateinit var core: PeerPass
        private set

    override fun onCreate() {
        super.onCreate()
        instance = this
        val secret = IdentityStore.loadOrCreate(this)
        core = PeerPass(File(filesDir, "peerpass.db").path, secret, Prefs.port(this).toUShort())
        secret.fill(0)
        Vault.init(this, core)
        SyncWorker.schedulePeriodic(this)
        // Lock when the screen turns off.
        registerReceiver(object : BroadcastReceiver() {
            override fun onReceive(c: Context, i: Intent) = Vault.lock()
        }, IntentFilter(Intent.ACTION_SCREEN_OFF), Context.RECEIVER_NOT_EXPORTED)
    }

    companion object {
        lateinit var instance: PeerPassApp
            private set
    }
}

object Prefs {
    private fun p(c: Context) = c.getSharedPreferences("settings", Context.MODE_PRIVATE)
    fun port(c: Context) = p(c).getInt("port", 47823)
    fun autoLockMinutes(c: Context) = p(c).getInt("auto_lock_min", 5)
    fun setAutoLockMinutes(c: Context, m: Int) = p(c).edit().putInt("auto_lock_min", m).apply()
    fun onboarded(c: Context) = p(c).getBoolean("onboarded", false)
    fun setOnboarded(c: Context) = p(c).edit().putBoolean("onboarded", true).apply()
}
