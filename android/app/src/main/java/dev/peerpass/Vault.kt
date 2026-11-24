package dev.peerpass

import android.content.Context
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.setValue
import uniffi.peerpass_ffi.EventListener
import uniffi.peerpass_ffi.PeerPass

/** App-wide vault state: change counter for Compose, idle auto-lock, sync triggers. */
object Vault {
    lateinit var core: PeerPass
        private set
    private lateinit var app: Context
    private val main = Handler(Looper.getMainLooper())
    private var lastTouch = SystemClock.elapsedRealtime()

    /** Bumped on every change; Compose screens reload when it changes. */
    var rev by mutableIntStateOf(0)
        private set

    fun init(c: Context, core: PeerPass) {
        app = c.applicationContext
        this.core = core
        core.setListener(object : EventListener {
            override fun onChange() {
                main.post { rev++ }
            }
        })
        main.postDelayed(::checkIdle, 10_000)
    }

    fun bump() {
        rev++
    }

    fun touch() {
        lastTouch = SystemClock.elapsedRealtime()
    }

    fun lock() {
        if (::core.isInitialized && core.isUnlocked()) {
            core.lock()
            main.post { rev++ }
        }
    }

    private fun checkIdle() {
        val limit = Prefs.autoLockMinutes(app) * 60_000L
        if (core.isUnlocked() && SystemClock.elapsedRealtime() - lastTouch > limit) lock()
        main.postDelayed(::checkIdle, 10_000)
    }

    /** After a local edit: sync now (expedited job; also runs while the app is closed). */
    fun edited() {
        rev++
        SyncWorker.syncSoon(app)
    }
}
