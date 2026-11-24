package dev.peerpass.ui

import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import dev.peerpass.BiometricStore
import dev.peerpass.Prefs
import dev.peerpass.Vault
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.peerpass_ffi.PairStatus

@Composable
fun AppRoot(act: FragmentActivity) {
    val rev = Vault.rev
    val core = Vault.core
    val hasVault = remember(rev) { runCatching { core.hasVault() }.getOrDefault(false) }
    val pair = remember(rev) { core.pairStatus() }
    val unlocked = remember(rev) { core.isUnlocked() }
    var onboarded by remember { mutableStateOf(Prefs.onboarded(act)) }
    when {
        !hasVault || (pair.joining && !pair.joinDone) -> SetupScreen(pair)
        !unlocked -> UnlockScreen(act) { Vault.bump() }
        !onboarded -> OnboardingScreen { Prefs.setOnboarded(act); onboarded = true }
        else -> MainNav(act)
    }
}

@Composable
fun PasswordField(value: String, label: String, onDone: (() -> Unit)? = null, onChange: (String) -> Unit) {
    OutlinedTextField(
        value, onChange, label = { Text(label) }, singleLine = true,
        visualTransformation = PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, imeAction = if (onDone != null) ImeAction.Done else ImeAction.Next),
        keyboardActions = KeyboardActions(onDone = { onDone?.invoke() }),
        modifier = Modifier.fillMaxWidth(),
    )
}

@Composable
fun SetupScreen(pair: PairStatus) {
    val core = Vault.core
    val scope = rememberCoroutineScope()
    val ctx = LocalContext.current
    var name by remember { mutableStateOf(android.os.Build.MODEL ?: "Phone") }
    var pw by remember { mutableStateOf("") }
    var pw2 by remember { mutableStateOf("") }
    var text by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var err by remember { mutableStateOf<String?>(null) }
    val scan = rememberLauncherForActivityResult(ScanContract()) { r -> r.contents?.let { text = it } }
    val netPerm = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { }
    fun join() {
        if (needsLocalNetworkPermission() && ContextCompat.checkSelfPermission(ctx, LOCAL_NETWORK_PERMISSION) != PackageManager.PERMISSION_GRANTED) {
            netPerm.launch(LOCAL_NETWORK_PERMISSION)
        }
        core.pairJoin(text.trim(), name.trim())
        Vault.bump()
    }

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp), verticalArrangement = gap) {
        if (pair.joining && !pair.joinDone) {
            Text("Joining vault…", style = MaterialTheme.typography.headlineSmall)
            val code = pair.joinCode
            if (code == null) Text("Connecting to the other device…")
            else {
                Text("Check that the other device shows the same code, then accept there:")
                Text(code, style = MaterialTheme.typography.displayMedium)
            }
            return@Column
        }
        Text("peerpass", style = MaterialTheme.typography.displaySmall, color = MaterialTheme.colorScheme.primary, fontWeight = androidx.compose.ui.text.font.FontWeight.ExtraBold)
        pair.joinError?.let { ErrorText("Joining failed: $it") }
        Text("Create a new vault", style = MaterialTheme.typography.headlineSmall)
        Text("Use this on your first device.")
        OutlinedTextField(name, { name = it }, label = { Text("Device name") }, singleLine = true, modifier = Modifier.fillMaxWidth())
        PasswordField(pw, "Master password") { pw = it }
        PasswordField(pw2, "Repeat master password") { pw2 = it }
        ErrorText(err)
        Button(enabled = !busy, onClick = {
            err = when {
                pw != pw2 -> "Passwords do not match."
                pw.length < 8 -> "Use at least 8 characters."
                else -> null
            }
            if (err == null) scope.launch {
                busy = true
                err = withContext(Dispatchers.IO) { runCatching { core.createVault(pw, name.trim()) }.exceptionOrNull()?.let(::errMsg) }
                busy = false
                Vault.bump()
            }
        }) { Text(if (busy) "Creating…" else "Create vault") }
        HorizontalDivider(Modifier.padding(vertical = 8.dp))
        Text("Join an existing vault", style = MaterialTheme.typography.headlineSmall)
        Text("On a paired device open Devices → Pair new device, then scan its QR code or paste the text.")
        OutlinedButton(onClick = {
            scan.launch(ScanOptions().setDesiredBarcodeFormats(ScanOptions.QR_CODE).setOrientationLocked(false).setBeepEnabled(false).setPrompt("Scan the peerpass pairing code"))
        }) { Text("Scan QR code") }
        OutlinedTextField(text, { text = it }, label = { Text("…or paste pairing text") }, modifier = Modifier.fillMaxWidth())
        Button(enabled = text.isNotBlank(), onClick = ::join) { Text("Join") }
    }
}

/** Password or fingerprint unlock. Shared by the app and the autofill auth screen. */
@Composable
fun UnlockScreen(act: FragmentActivity, onUnlocked: () -> Unit) {
    val core = Vault.core
    val scope = rememberCoroutineScope()
    var pw by remember { mutableStateOf("") }
    var err by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    var offerBio by remember { mutableStateOf(false) }
    val fp = remember { runCatching { core.headerFingerprint() }.getOrNull() }
    val bioReady = remember { fp != null && canUseBiometrics(act) && BiometricStore.isEnrolled(act, fp) }

    fun bioUnlock() {
        val cipher = BiometricStore.decryptCipher(act) ?: run { err = "Fingerprints changed — use your master password."; return }
        biometricPrompt(act, "Unlock peerpass", cipher, onOk = { c ->
            val key = BiometricStore.unwrap(act, c)
            try {
                core.unlockWithKey(key)
                onUnlocked()
            } catch (e: Exception) {
                BiometricStore.clear(act)
                err = "Fingerprint unlock is no longer valid — use your master password."
            } finally {
                key.fill(0)
            }
        }, onErr = { err = it })
    }

    LaunchedEffect(Unit) { if (bioReady) bioUnlock() }

    fun unlock() = scope.launch {
        busy = true
        val e = withContext(Dispatchers.IO) { runCatching { core.unlock(pw) }.exceptionOrNull() }
        busy = false
        pw = ""
        if (e != null) err = errMsg(e)
        else if (fp != null && canUseBiometrics(act) && !BiometricStore.isEnrolled(act, core.headerFingerprint())) offerBio = true
        else onUnlocked()
    }

    Column(Modifier.fillMaxSize().padding(20.dp), verticalArrangement = gap) {
        Text("peerpass", style = MaterialTheme.typography.displaySmall, color = MaterialTheme.colorScheme.primary, fontWeight = androidx.compose.ui.text.font.FontWeight.ExtraBold)
        Text("Unlock your vault", style = MaterialTheme.typography.headlineSmall)
        core.deviceName()?.let { Text("This device: $it", color = MaterialTheme.colorScheme.onSurfaceVariant) }
        PasswordField(pw, "Master password", onDone = { unlock() }) { pw = it }
        ErrorText(err)
        Row(horizontalArrangement = gap) {
            Button(enabled = !busy && pw.isNotEmpty(), onClick = { unlock() }) { Text(if (busy) "Unlocking…" else "Unlock") }
            if (bioReady) OutlinedButton(onClick = ::bioUnlock) { Text("Use fingerprint") }
        }
    }

    if (offerBio) AlertDialog(
        onDismissRequest = { offerBio = false; onUnlocked() },
        title = { Text("Unlock with fingerprint?") },
        text = { Text("Next time you can unlock with your fingerprint. A new master password or new fingerprints turn this off again.") },
        confirmButton = {
            TextButton(onClick = {
                offerBio = false
                val key = core.exportKey()
                biometricPrompt(act, "Enable fingerprint unlock", BiometricStore.encryptCipher(), onOk = { c ->
                    BiometricStore.store(act, c, key, core.headerFingerprint())
                    key.fill(0)
                    onUnlocked()
                }, onErr = { key.fill(0); onUnlocked() })
            }) { Text("Enable") }
        },
        dismissButton = { TextButton(onClick = { offerBio = false; onUnlocked() }) { Text("Not now") } },
    )
}
