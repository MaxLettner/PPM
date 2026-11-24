package dev.peerpass

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import dev.peerpass.ui.AppRoot
import dev.peerpass.ui.PeerPassTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : FragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // No screenshots / recents thumbnails of vault content.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        setContent { PeerPassTheme { AppRoot(this) } }
        // While visible: listen + mDNS (peers sync when they appear) and sync every 5 min.
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                visible = true
                withContext(Dispatchers.IO) { Net.start(this@MainActivity) }
                try {
                    while (true) {
                        withContext(Dispatchers.IO) { Vault.core.syncAll() }
                        Vault.bump()
                        delay(5 * 60_000L)
                    }
                } finally {
                    visible = false
                    withContext(Dispatchers.IO + kotlinx.coroutines.NonCancellable) { Net.stop() }
                }
            }
        }
    }

    override fun onUserInteraction() {
        super.onUserInteraction()
        Vault.touch()
    }

    companion object {
        @Volatile
        var visible = false
    }
}
