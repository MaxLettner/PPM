package dev.peerpass.ui

import android.os.Build
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Surface
import androidx.compose.material3.darkColorScheme
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
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

/** Catppuccin Macchiato (accent: mauve). */
object Mocha {
    val base = Color(0xFF24273A)
    val mantle = Color(0xFF1E2030)
    val crust = Color(0xFF181926)
    val surface0 = Color(0xFF363A4F)
    val surface1 = Color(0xFF494D64)
    val surface2 = Color(0xFF5B6078)
    val overlay0 = Color(0xFF6E738D)
    val subtext0 = Color(0xFFA5ADCB)
    val text = Color(0xFFCAD3F5)
    val mauve = Color(0xFFC6A0F6)
    val lavender = Color(0xFFB7BDF8)
    val pink = Color(0xFFF5BDE6)
    val red = Color(0xFFED8796)
    val green = Color(0xFFA6DA95)
    val accents = listOf(
        mauve, Color(0xFF8AADF4), green, Color(0xFFF5A97F), pink, Color(0xFF8BD5CA), Color(0xFFEED49F),
    )
}

private val macchiato = darkColorScheme(
    primary = Mocha.mauve, onPrimary = Mocha.crust,
    primaryContainer = Mocha.surface1, onPrimaryContainer = Mocha.lavender,
    secondary = Mocha.lavender, onSecondary = Mocha.crust,
    secondaryContainer = Mocha.surface0, onSecondaryContainer = Mocha.text,
    tertiary = Mocha.pink, onTertiary = Mocha.crust,
    background = Mocha.base, onBackground = Mocha.text,
    surface = Mocha.base, onSurface = Mocha.text,
    surfaceVariant = Mocha.surface0, onSurfaceVariant = Mocha.subtext0,
    surfaceContainerLowest = Mocha.crust, surfaceContainerLow = Mocha.mantle,
    surfaceContainer = Mocha.mantle, surfaceContainerHigh = Mocha.surface0, surfaceContainerHighest = Mocha.surface1,
    inverseSurface = Mocha.text, inverseOnSurface = Mocha.base,
    outline = Mocha.overlay0, outlineVariant = Mocha.surface0,
    error = Mocha.red, onError = Mocha.crust, errorContainer = Mocha.red.copy(alpha = 0.2f), onErrorContainer = Mocha.red,
)

@Composable
fun PeerPassTheme(content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = macchiato) {
        Surface(color = Mocha.base, contentColor = Mocha.text, modifier = Modifier.fillMaxSize(), content = content)
    }
}

/** Letter avatar with a stable accent color per title. */
@Composable
fun Avatar(title: String, size: Int = 40) {
    val ch = title.firstOrNull { it.isLetterOrDigit() }?.uppercaseChar() ?: '?'
    val color = Mocha.accents[(title.fold(0) { a, c -> a * 31 + c.code } and 0x7fffffff) % Mocha.accents.size]
    Box(Modifier.size(size.dp).clip(CircleShape).background(color), contentAlignment = Alignment.Center) {
        Text(ch.toString(), color = Mocha.crust, fontWeight = FontWeight.ExtraBold, fontSize = (size * 0.42f).sp)
    }
}

/** Grouped fields on a raised surface. */
@Composable
fun FieldCard(content: @Composable ColumnScope.() -> Unit) {
    Column(
        Modifier.fillMaxWidth().clip(RoundedCornerShape(16.dp)).background(Mocha.mantle).padding(horizontal = 14.dp, vertical = 4.dp),
        content = content,
    )
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
            Text(
                if (shown) value else "•".repeat(minOf(value.length, 16)),
                fontFamily = if (secret) FontFamily.Monospace else null,
                color = if (secret) Mocha.green else Mocha.text,
            )
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
