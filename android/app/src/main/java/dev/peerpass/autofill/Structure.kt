package dev.peerpass.autofill

import android.app.assist.AssistStructure
import android.text.InputType
import android.view.View
import android.view.autofill.AutofillId

/** Username/password fields and the page/app identity found in an AssistStructure. */
class ParsedForm(
    val packageName: String,
    val webDomain: String?,
    val username: AutofillId?,
    val password: AutofillId?,
    val usernameValue: String?,
    val passwordValue: String?,
) {
    val ids: Array<AutofillId> get() = listOfNotNull(username, password).toTypedArray()
}

private fun isPassword(n: AssistStructure.ViewNode): Boolean {
    n.autofillHints?.let { h -> if (h.any { it.contains("password", true) }) return true }
    n.htmlInfo?.attributes?.forEach { if (it.first == "type" && it.second == "password") return true }
    val cls = n.inputType and InputType.TYPE_MASK_CLASS
    val v = n.inputType and InputType.TYPE_MASK_VARIATION
    return (cls == InputType.TYPE_CLASS_TEXT && (v == InputType.TYPE_TEXT_VARIATION_PASSWORD ||
        v == InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD || v == InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD)) ||
        (cls == InputType.TYPE_CLASS_NUMBER && v == InputType.TYPE_NUMBER_VARIATION_PASSWORD)
}

private val userWords = listOf("user", "email", "login", "account", "e-mail", "username")

private fun isUsername(n: AssistStructure.ViewNode): Boolean {
    n.autofillHints?.let { h ->
        if (h.any { it == View.AUTOFILL_HINT_USERNAME || it == View.AUTOFILL_HINT_EMAIL_ADDRESS || it.contains("username", true) || it.contains("email", true) }) return true
    }
    n.htmlInfo?.attributes?.forEach {
        if (it.first == "type" && it.second == "email") return true
        if (it.first in listOf("name", "id", "autocomplete") && userWords.any { w -> it.second?.contains(w, true) == true }) return true
    }
    val v = n.inputType and InputType.TYPE_MASK_VARIATION
    if (n.inputType and InputType.TYPE_MASK_CLASS == InputType.TYPE_CLASS_TEXT &&
        (v == InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS || v == InputType.TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS)) return true
    val text = listOfNotNull(n.idEntry, n.hint?.toString()).joinToString(" ")
    return userWords.any { text.contains(it, true) }
}

fun parse(s: AssistStructure): ParsedForm {
    var domain: String? = null
    var user: AssistStructure.ViewNode? = null
    var pass: AssistStructure.ViewNode? = null
    var lastText: AssistStructure.ViewNode? = null
    fun walk(n: AssistStructure.ViewNode) {
        n.webDomain?.takeIf { it.isNotBlank() }?.let { if (domain == null) domain = it }
        if (n.autofillId != null && n.autofillType == View.AUTOFILL_TYPE_TEXT && n.visibility == View.VISIBLE) {
            when {
                pass == null && isPassword(n) -> { pass = n; if (user == null) user = lastText }
                user == null && isUsername(n) -> user = n
                else -> lastText = n
            }
        }
        for (i in 0 until n.childCount) walk(n.getChildAt(i))
    }
    for (i in 0 until s.windowNodeCount) walk(s.getWindowNodeAt(i).rootViewNode)
    return ParsedForm(
        s.activityComponent.packageName, domain, user?.autofillId, pass?.autofillId,
        user?.autofillValue?.takeIf { it.isText }?.textValue?.toString(),
        pass?.autofillValue?.takeIf { it.isText }?.textValue?.toString(),
    )
}
