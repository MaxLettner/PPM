package dev.peerpass

import android.content.Context
import android.net.wifi.WifiManager

/** mDNS needs a MulticastLock on Android while discovering. */
object Net {
    private var lock: WifiManager.MulticastLock? = null

    @Synchronized
    fun acquire(c: Context) {
        if (lock?.isHeld == true) return
        lock = c.applicationContext.getSystemService(WifiManager::class.java)
            .createMulticastLock("peerpass-mdns").apply { setReferenceCounted(false); acquire() }
    }

    @Synchronized
    fun release() {
        lock?.takeIf { it.isHeld }?.release()
        lock = null
    }

    /** Foreground: listen + discover. */
    fun start(c: Context) {
        acquire(c)
        runCatching { Vault.core.startNetwork() }
    }

    fun stop() {
        Vault.core.stopNetwork()
        release()
    }
}
