package dev.peerpass.ui

import android.content.pm.PackageManager
import android.graphics.Bitmap
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.FilterQuality
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.google.zxing.BarcodeFormat
import com.journeyapps.barcodescanner.BarcodeEncoder
import dev.peerpass.BiometricStore
import dev.peerpass.Clipboard
import dev.peerpass.DeviceSettings
import dev.peerpass.Prefs
import dev.peerpass.Vault
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.peerpass_ffi.kdfBenchmarkMillis

private fun qr(text: String): Bitmap = BarcodeEncoder().encodeBitmap(text, BarcodeFormat.QR_CODE, 600, 600)

@Composable
fun DevicesScreen() {
    val core = Vault.core
    val rev = Vault.rev
    val c = LocalContext.current
    val scope = rememberCoroutineScope()
    val peers = remember(rev) { runCatching { core.peers() }.getOrDefault(emptyList()) }
    val pair = remember(rev) { core.pairStatus() }
    var offer by remember { mutableStateOf<String?>(null) }
    var left by remember { mutableStateOf(300) }
    var remove by remember { mutableStateOf<Pair<String, String>?>(null) }
    var msg by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(offer) {
        left = 300
        while (offer != null && left > 0) { delay(1000); left-- }
        if (offer != null) { core.pairCancel(); offer = null }
    }

    val o = offer
    if (o == null) Button(onClick = {
        runCatching { core.pairBegin() }.onSuccess { offer = it }.onFailure { msg = errMsg(it) }
    }) { Text("Pair new device") }
    else {
        Text("Scan this code with the new device, or copy the text into it. Valid once, for ${left / 60}:${"%02d".format(left % 60)}.")
        val bmp = remember(o) { qr(o) }
        Image(bmp.asImageBitmap(), "Pairing QR code", Modifier.size(280.dp), filterQuality = FilterQuality.None)
        Text(o, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
        Row(horizontalArrangement = gap) {
            OutlinedButton(onClick = { Clipboard.copy(c, "Pairing", o) }) { Text("Copy text") }
            OutlinedButton(onClick = { core.pairCancel(); offer = null }) { Text("Cancel") }
        }
    }
    msg?.let { Text(it) }
    HorizontalDivider()
    if (peers.isEmpty()) Text("No other devices yet.")
    peers.forEach { p ->
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(p.name)
                Text("last sync ${ago(p.lastSync)} · ${p.lastAddr ?: "address unknown"}", style = MaterialTheme.typography.bodySmall)
            }
            TextButton(onClick = { remove = p.deviceId to p.name }) { Text("Remove") }
        }
    }
    OutlinedButton(onClick = {
        scope.launch {
            val r = withContext(Dispatchers.IO) { core.syncAll() }
            msg = if (r.isEmpty()) "No paired devices." else r.joinToString("\n") { if (it.ok) "${it.name}: synced" else "${it.name}: ${it.error}" }
            Vault.bump()
        }
    }) { Text("Sync now") }
    Text("Removing a device stops syncing with it. It keeps the data it already has; the vault key is not rotated.", style = MaterialTheme.typography.bodySmall)

    val pName = pair.pendingName
    if (pName != null) AlertDialog(
        onDismissRequest = {},
        title = { Text("Accept device “$pName”?") },
        text = { Text("Code ${pair.pendingCode}\nOnly accept if the other device shows the same code.") },
        confirmButton = { TextButton(onClick = { core.pairRespond(true); offer = null; Vault.bump() }) { Text("Accept") } },
        dismissButton = { TextButton(onClick = { core.pairRespond(false); offer = null; Vault.bump() }) { Text("Reject") } },
    )
    remove?.let { (id, name) ->
        AlertDialog(
            onDismissRequest = { remove = null },
            title = { Text("Remove “$name”?") },
            text = { Text("It will no longer sync with your devices.") },
            confirmButton = { TextButton(onClick = { core.removePeer(id); Vault.edited(); remove = null }) { Text("Remove") } },
            dismissButton = { TextButton(onClick = { remove = null }) { Text("Cancel") } },
        )
    }
}

@Composable
fun BackgroundSyncSettings() {
    val c = LocalContext.current
    val rev = Vault.rev
    val ignoring = remember(rev) { DeviceSettings.ignoringBatteryOptimizations(c) }
    val netPerm = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { Vault.bump() }
    Text("Background sync", style = MaterialTheme.typography.titleMedium)
    Text("Doke OS stops background apps aggressively. For sync while peerpass is closed:")
    Row(verticalAlignment = Alignment.CenterVertically) {
        Text(if (ignoring) "✓ Battery optimisation is off" else "1. Turn off battery optimisation", Modifier.weight(1f))
        if (!ignoring) OutlinedButton(onClick = { DeviceSettings.requestIgnoreBatteryOptimizations(c) }) { Text("Open") }
    }
    Row(verticalAlignment = Alignment.CenterVertically) {
        Text("2. Allow auto-start (Doke OS: App info → Auto-start / Startup manager)", Modifier.weight(1f))
        OutlinedButton(onClick = { DeviceSettings.openAutoStart(c) }) { Text("Open") }
    }
    Row(verticalAlignment = Alignment.CenterVertically) {
        Text("3. Use peerpass for autofill", Modifier.weight(1f))
        OutlinedButton(onClick = { DeviceSettings.openAutofillSettings(c) }) { Text("Open") }
    }
    if (needsLocalNetworkPermission() && ContextCompat.checkSelfPermission(c, LOCAL_NETWORK_PERMISSION) != PackageManager.PERMISSION_GRANTED) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("4. Allow local network access", Modifier.weight(1f))
            OutlinedButton(onClick = { netPerm.launch(LOCAL_NETWORK_PERMISSION) }) { Text("Allow") }
        }
    }
}

@Composable
fun OnboardingScreen(done: () -> Unit) {
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp), verticalArrangement = gap) {
        Text("Almost done", style = MaterialTheme.typography.headlineSmall)
        BackgroundSyncSettings()
        Button(onClick = done) { Text("Continue") }
    }
}

@Composable
fun SettingsScreen(act: FragmentActivity) {
    val core = Vault.core
    val rev = Vault.rev
    val scope = rememberCoroutineScope()
    var autoLock by remember { mutableStateOf(Prefs.autoLockMinutes(act)) }
    var old by remember { mutableStateOf("") }
    var new1 by remember { mutableStateOf("") }
    var new2 by remember { mutableStateOf("") }
    var msg by remember { mutableStateOf<String?>(null) }
    var bench by remember { mutableStateOf<String?>(null) }
    val peers = remember(rev) { runCatching { core.peers() }.getOrDefault(emptyList()) }

    Text("This device: ${core.deviceName() ?: "?"} (${core.deviceId()})", style = MaterialTheme.typography.bodySmall)
    Text("Auto-lock", style = MaterialTheme.typography.titleMedium)
    Text("Also locks when the screen turns off.")
    listOf(1, 5, 15, 60).forEach { m ->
        Row(verticalAlignment = Alignment.CenterVertically) {
            RadioButton(autoLock == m, { autoLock = m; Prefs.setAutoLockMinutes(act, m) })
            Text("after $m min")
        }
    }
    HorizontalDivider()
    Text("Sync status", style = MaterialTheme.typography.titleMedium)
    if (peers.isEmpty()) Text("No paired devices.")
    peers.forEach { Text("${it.name} — last sync ${ago(it.lastSync)}") }
    HorizontalDivider()
    BackgroundSyncSettings()
    HorizontalDivider()
    Text("Fingerprint unlock", style = MaterialTheme.typography.titleMedium)
    val enrolled = remember(rev) { runCatching { BiometricStore.isEnrolled(act, core.headerFingerprint()) }.getOrDefault(false) }
    if (enrolled) OutlinedButton(onClick = { BiometricStore.clear(act); Vault.bump() }) { Text("Turn off fingerprint unlock") }
    else Text("Offered after the next password unlock.")
    HorizontalDivider()
    Text("Change master password", style = MaterialTheme.typography.titleMedium)
    Text("Applies to all devices after they sync.")
    PasswordField(old, "Current password") { old = it }
    PasswordField(new1, "New password") { new1 = it }
    PasswordField(new2, "Repeat new password") { new2 = it }
    Button(onClick = {
        if (new1 != new2) { msg = "New passwords do not match."; return@Button }
        if (new1.length < 8) { msg = "Use at least 8 characters."; return@Button }
        scope.launch {
            msg = withContext(Dispatchers.IO) { runCatching { core.changePassword(old, new1) }.exceptionOrNull()?.let(::errMsg) }
                ?: "Master password changed."
            old = ""; new1 = ""; new2 = ""
            BiometricStore.clear(act)
            Vault.edited()
        }
    }) { Text("Change password") }
    msg?.let { Text(it) }
    HorizontalDivider()
    Text("Key derivation speed", style = MaterialTheme.typography.titleMedium)
    OutlinedButton(onClick = { scope.launch { bench = "${withContext(Dispatchers.Default) { kdfBenchmarkMillis() }} ms per unlock (target 500–1000 ms)" } }) { Text("Measure") }
    bench?.let { Text(it) }
}

@Composable
fun ImportScreen() {
    val c = LocalContext.current
    val scope = rememberCoroutineScope()
    var kdbx by remember { mutableStateOf(true) }
    var pw by remember { mutableStateOf("") }
    var msg by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    val pick = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        scope.launch {
            busy = true
            msg = withContext(Dispatchers.IO) {
                runCatching {
                    val data = c.contentResolver.openInputStream(uri)!!.use { it.readBytes() }
                    try {
                        Vault.core.importData(if (kdbx) "kdbx" else "bitwarden", data, pw)
                    } finally {
                        data.fill(0)
                    }
                }.fold({ "Imported ${it.imported} entries, skipped ${it.skipped} duplicates." }, ::errMsg)
            }
            busy = false
            pw = ""
            Vault.edited()
        }
    }
    Text("Entries with the same title, username and website as an existing one are skipped.")
    Row(verticalAlignment = Alignment.CenterVertically) { RadioButton(kdbx, { kdbx = true }); Text("KeePass (.kdbx, KDBX4)") }
    Row(verticalAlignment = Alignment.CenterVertically) { RadioButton(!kdbx, { kdbx = false }); Text("Bitwarden (unencrypted .json)") }
    if (kdbx) PasswordField(pw, "KeePass database password") { pw = it }
    Button(enabled = !busy, onClick = { pick.launch(arrayOf("*/*")) }) { Text(if (busy) "Importing…" else "Choose file") }
    msg?.let { Text(it) }
    Text("Delete the export file afterwards — it is not encrypted.", style = MaterialTheme.typography.bodySmall)
}
