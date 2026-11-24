package dev.peerpass.ui

import android.os.Build
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import dev.peerpass.Clipboard
import javax.crypto.Cipher

@Composable
fun PeerPassTheme(content: @Composable () -> Unit) {
    val c = LocalContext.current
    MaterialTheme(colorScheme = if (isSystemInDarkTheme()) dynamicDarkColorScheme(c) else dynamicLightColorScheme(c), content = content)
}

/** Label + value with optional reveal and a copy button (copies as sensitive, auto-clears). */
@Composable
fun FieldRow(label: String, value: String, secret: Boolean = false) {
    if (value.isEmpty()) return
    val c = LocalContext.current
    var shown by remember(value) { mutableStateOf(!secret) }
    Row(Modifier.fillMaxWidth().padding(vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(if (shown) value else "•".repeat(minOf(value.length, 16)), fontFamily = if (secret) FontFamily.Monospace else null)
        }
        if (secret) TextButton(onClick = { shown = !shown }) { Text(if (shown) "Hide" else "Show") }
        TextButton(onClick = { Clipboard.copy(c, label, value) }) { Text("Copy") }
    }
}

@Composable
fun ErrorText(e: String?) {
    if (e != null) Text(e, color = MaterialTheme.colorScheme.error, modifier = Modifier.padding(vertical = 4.dp))
}

val gap = Arrangement.spacedBy(10.dp)

fun ago(ts: Long?): String {
    if (ts == null) return "never"
    val d = System.currentTimeMillis() / 1000 - ts
    return when {
        d < 60 -> "just now"
        d < 3600 -> "${d / 60} min ago"
        d < 86400 -> "${d / 3600} h ago"
        else -> "${d / 86400} days ago"
    }
}

fun errMsg(e: Throwable): String = e.message ?: e.toString()

fun canUseBiometrics(act: FragmentActivity) =
    BiometricManager.from(act).canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS

fun biometricPrompt(act: FragmentActivity, title: String, cipher: Cipher, onOk: (Cipher) -> Unit, onErr: (String) -> Unit) {
    val p = BiometricPrompt(act, ContextCompat.getMainExecutor(act), object : BiometricPrompt.AuthenticationCallback() {
        override fun onAuthenticationSucceeded(r: BiometricPrompt.AuthenticationResult) {
            r.cryptoObject?.cipher?.let(onOk) ?: onErr("no cipher")
        }

        override fun onAuthenticationError(code: Int, msg: CharSequence) = onErr(msg.toString())
    })
    val info = BiometricPrompt.PromptInfo.Builder()
        .setTitle(title)
        .setNegativeButtonText("Use password")
        .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
        .build()
    p.authenticate(info, BiometricPrompt.CryptoObject(cipher))
}

/** Android 17+ asks for local-network access at runtime when targeting SDK 37. */
const val LOCAL_NETWORK_PERMISSION = "android.permission.ACCESS_LOCAL_NETWORK"
fun needsLocalNetworkPermission() = Build.VERSION.SDK_INT >= 37
