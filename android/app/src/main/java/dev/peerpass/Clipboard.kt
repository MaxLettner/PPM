package dev.peerpass

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle

/** Copies as a sensitive clip and clears it after 30 s. */
object Clipboard {
    private const val CLEAR_MS = 30_000L
    private var generation = 0
    private val main = Handler(Looper.getMainLooper())

    fun copy(c: Context, label: String, text: String) {
        val cm = c.getSystemService(ClipboardManager::class.java)
        val clip = ClipData.newPlainText(label, text)
        clip.description.extras = PersistableBundle().apply { putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true) }
        cm.setPrimaryClip(clip)
        val g = ++generation
        main.postDelayed({ if (g == generation) cm.clearPrimaryClip() }, CLEAR_MS)
    }
}
