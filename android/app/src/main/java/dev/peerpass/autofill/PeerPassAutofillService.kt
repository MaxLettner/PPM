package dev.peerpass.autofill

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.Dataset
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.SaveCallback
import android.service.autofill.SaveInfo
import android.service.autofill.SaveRequest
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import dev.peerpass.Vault
import uniffi.peerpass_ffi.Credential
import uniffi.peerpass_ffi.EntryData

/** Fills on user selection only (the system shows our datasets; nothing fills on load). */
class PeerPassAutofillService : AutofillService() {
    override fun onFillRequest(req: FillRequest, cancel: CancellationSignal, cb: FillCallback) {
        val form = parse(req.fillContexts.last().structure)
        if (form.packageName == packageName || form.ids.isEmpty()) return cb.onSuccess(null)
        val core = Vault.core
        if (!core.isUnlocked()) {
            val sender = AutofillAuthActivity.intent(this, form, AutofillAuthActivity.MODE_FILL).intentSender
            val resp = FillResponse.Builder()
                .setAuthentication(form.ids, sender, presentation(this, "Unlock peerpass", form.webDomain ?: form.packageName))
            saveInfo(form)?.let { resp.setSaveInfo(it) }
            return cb.onSuccess(resp.build())
        }
        cb.onSuccess(buildResponse(this, form))
    }

    override fun onSaveRequest(req: SaveRequest, cb: SaveCallback) {
        val form = parse(req.fillContexts.last().structure)
        val pw = form.passwordValue
        if (pw.isNullOrEmpty()) return cb.onSuccess()
        if (Vault.core.isUnlocked()) {
            runCatching { saveLogin(form) }.onSuccess { cb.onSuccess() }.onFailure { cb.onFailure(it.message) }
        } else {
            cb.onSuccess(AutofillAuthActivity.intent(this, form, AutofillAuthActivity.MODE_SAVE).intentSender)
        }
    }

    companion object {
        fun presentation(c: Context, title: String, sub: String): RemoteViews =
            RemoteViews(c.packageName, android.R.layout.simple_list_item_2).apply {
                setTextViewText(android.R.id.text1, title)
                setTextViewText(android.R.id.text2, sub)
            }

        fun saveInfo(f: ParsedForm): SaveInfo? {
            val p = f.password ?: return null
            val type = SaveInfo.SAVE_DATA_TYPE_PASSWORD or (if (f.username != null) SaveInfo.SAVE_DATA_TYPE_USERNAME else 0)
            return SaveInfo.Builder(type, arrayOf(p)).apply { f.username?.let { setOptionalIds(arrayOf(it)) } }.build()
        }

        fun candidates(f: ParsedForm): List<Credential> =
            Vault.core.findForAutofill(f.webDomain, if (f.webDomain == null) f.packageName else null)

        /** Datasets for every matching entry version (conflicts labelled). Requires unlock. */
        @Suppress("DEPRECATION") // Dataset.setValue(id, value, presentation) is the simplest form on API 33+
        fun buildResponse(c: Context, f: ParsedForm): FillResponse? {
            val creds = candidates(f)
            val b = FillResponse.Builder()
            for (cr in creds) {
                val label = listOf(cr.username, cr.label).filter { it.isNotEmpty() }.joinToString(" · ")
                val p = presentation(c, cr.title, label)
                val d = Dataset.Builder()
                f.username?.let { d.setValue(it, AutofillValue.forText(cr.username), p) }
                f.password?.let { d.setValue(it, AutofillValue.forText(cr.password), p) }
                b.addDataset(d.build())
            }
            val save = saveInfo(f)
            if (creds.isEmpty() && save == null) return null
            save?.let { b.setSaveInfo(it) }
            return b.build()
        }

        fun saveLogin(f: ParsedForm) {
            val url = f.webDomain?.let { "https://$it" } ?: "androidapp://${f.packageName}"
            val title = f.webDomain ?: f.packageName
            Vault.core.put(null, EntryData(title, f.usernameValue ?: "", f.passwordValue ?: "", listOf(url), "", null, emptyList(), 0L))
            Vault.edited()
        }
    }
}

internal fun pendingFlags() = PendingIntent.FLAG_CANCEL_CURRENT or PendingIntent.FLAG_MUTABLE
internal fun Intent.toPending(c: Context, code: Int) = PendingIntent.getActivity(c, code, this, pendingFlags())
