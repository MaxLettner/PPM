package dev.peerpass.autofill

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.view.WindowManager
import android.view.autofill.AutofillId
import android.view.autofill.AutofillManager
import androidx.activity.compose.setContent
import androidx.fragment.app.FragmentActivity
import dev.peerpass.Vault
import dev.peerpass.ui.PeerPassTheme
import dev.peerpass.ui.UnlockScreen

/** Unlock screen shown by autofill when the vault is locked; then fills or saves. */
class AutofillAuthActivity : FragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        if (Vault.core.isUnlocked()) return finishWithResult()
        setContent { PeerPassTheme { UnlockScreen(this) { finishWithResult() } } }
    }

    private fun form(): ParsedForm {
        val i = intent
        @Suppress("DEPRECATION")
        fun id(k: String) = i.getParcelableExtra(k, AutofillId::class.java)
        return ParsedForm(
            i.getStringExtra(EXTRA_PACKAGE) ?: "", i.getStringExtra(EXTRA_DOMAIN), id(EXTRA_USER_ID), id(EXTRA_PASS_ID),
            i.getStringExtra(EXTRA_USER_VALUE), i.getStringExtra(EXTRA_PASS_VALUE),
        )
    }

    private fun finishWithResult() {
        val f = form()
        if (intent.getIntExtra(EXTRA_MODE, MODE_FILL) == MODE_SAVE) {
            runCatching { PeerPassAutofillService.saveLogin(f) }
            setResult(RESULT_OK)
        } else {
            val resp = PeerPassAutofillService.buildResponse(this, f)
            setResult(RESULT_OK, Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, resp))
        }
        finish()
    }

    companion object {
        const val MODE_FILL = 0
        const val MODE_SAVE = 1
        private const val EXTRA_MODE = "mode"
        private const val EXTRA_PACKAGE = "package"
        private const val EXTRA_DOMAIN = "domain"
        private const val EXTRA_USER_ID = "user_id"
        private const val EXTRA_PASS_ID = "pass_id"
        private const val EXTRA_USER_VALUE = "user_value"
        private const val EXTRA_PASS_VALUE = "pass_value"
        private var requestCode = 0

        fun intent(c: Context, f: ParsedForm, mode: Int): PendingIntent {
            val i = Intent(c, AutofillAuthActivity::class.java)
                .putExtra(EXTRA_MODE, mode)
                .putExtra(EXTRA_PACKAGE, f.packageName)
                .putExtra(EXTRA_DOMAIN, f.webDomain)
                .putExtra(EXTRA_USER_ID, f.username)
                .putExtra(EXTRA_PASS_ID, f.password)
            // Values are only needed (and only passed, in-process) when saving.
            if (mode == MODE_SAVE) i.putExtra(EXTRA_USER_VALUE, f.usernameValue).putExtra(EXTRA_PASS_VALUE, f.passwordValue)
            return i.toPending(c, ++requestCode)
        }
    }
}
