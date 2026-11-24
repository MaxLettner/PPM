package dev.peerpass.ui

import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Badge
import androidx.compose.material3.BadgedBox
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Slider
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import dev.peerpass.Clipboard
import dev.peerpass.Vault
import kotlinx.coroutines.delay
import uniffi.peerpass_ffi.EntryData
import uniffi.peerpass_ffi.Field
import uniffi.peerpass_ffi.Item
import uniffi.peerpass_ffi.generatePassword

sealed interface Route {
    data object List : Route
    data class Entry(val id: String) : Route
    data class Edit(val id: String?) : Route
    data object Conflicts : Route
    data class Resolve(val id: String) : Route
    data object Devices : Route
    data object Settings : Route
    data object Generator : Route
    data object Import : Route
}

@Composable
fun MainNav(act: FragmentActivity) {
    val stack = remember { mutableStateListOf<Route>(Route.List) }
    val go: (Route) -> Unit = { stack.add(it) }
    val back: () -> Unit = { if (stack.size > 1) stack.removeAt(stack.lastIndex) }
    val home: () -> Unit = { stack.clear(); stack.add(Route.List) }
    BackHandler(enabled = stack.size > 1, onBack = back)
    when (val r = stack.last()) {
        Route.List -> ListScreen(go)
        is Route.Entry -> Screen("Entry", back) { EntryScreen(r.id, go, home) }
        is Route.Edit -> Screen(if (r.id == null) "New entry" else "Edit entry", back) {
            EditScreen(r.id) { id -> back(); if (r.id == null) go(Route.Entry(id)) }
        }
        Route.Conflicts -> Screen("Conflicts", back) { ConflictsScreen(go) }
        is Route.Resolve -> Screen("Resolve conflict", back) { ResolveScreen(r.id, home) }
        Route.Devices -> Screen("Devices", back) { DevicesScreen() }
        Route.Settings -> Screen("Settings", back) { SettingsScreen(act) }
        Route.Generator -> Screen("Password generator", back) { Generator(null) }
        Route.Import -> Screen("Import", back) { ImportScreen() }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun Screen(title: String, back: () -> Unit, content: @Composable () -> Unit) {
    Scaffold(topBar = {
        TopAppBar(title = { Text(title) }, navigationIcon = { TextButton(onClick = back) { Text("←") } })
    }) { pad ->
        Column(Modifier.padding(pad).fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = gap) {
            content()
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ListScreen(go: (Route) -> Unit) {
    val rev = Vault.rev
    val items = remember(rev) { runCatching { Vault.core.list() }.getOrDefault(emptyList()) }
    val conflicts = items.count { it.conflict }
    var q by remember { mutableStateOf("") }
    var menu by remember { mutableStateOf(false) }
    val shown = items.filter {
        q.isBlank() || it.title.contains(q, true) || it.username.contains(q, true) || it.urls.any { u -> u.contains(q, true) }
    }.sortedBy { it.title.lowercase() }
    Scaffold(
        topBar = {
            TopAppBar(title = { Text("peerpass") }, actions = {
                if (conflicts > 0) TextButton(onClick = { go(Route.Conflicts) }) {
                    BadgedBox(badge = { Badge { Text("$conflicts") } }) { Text("Conflicts") }
                }
                TextButton(onClick = { menu = true }) { Text("⋮") }
                DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
                    listOf("Generator" to Route.Generator, "Devices" to Route.Devices, "Import" to Route.Import, "Settings" to Route.Settings).forEach { (l, r) ->
                        DropdownMenuItem(text = { Text(l) }, onClick = { menu = false; go(r) })
                    }
                    DropdownMenuItem(text = { Text("Lock") }, onClick = { menu = false; Vault.lock() })
                }
            })
        },
        floatingActionButton = { FloatingActionButton(onClick = { go(Route.Edit(null)) }) { Text("+", style = MaterialTheme.typography.headlineSmall) } },
    ) { pad ->
        Column(Modifier.padding(pad)) {
            OutlinedTextField(q, { q = it }, label = { Text("Search") }, singleLine = true, modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp))
            if (shown.isEmpty()) Text(if (items.isEmpty()) "No entries yet. Tap + or import." else "Nothing matches.", Modifier.padding(16.dp))
            LazyColumn {
                items(shown, key = { it.id }) { s ->
                    ListItem(
                        headlineContent = { Text((if (s.conflict) "⚠ " else "") + s.title) },
                        supportingContent = { Text(s.username) },
                        modifier = Modifier.clickable { go(Route.Entry(s.id)) },
                    )
                }
            }
        }
    }
}

fun loadItem(id: String): Item? = runCatching { Vault.core.get(id) }.getOrNull()

@Composable
fun EntryScreen(id: String, go: (Route) -> Unit, home: () -> Unit) {
    val rev = Vault.rev
    val item = remember(rev) { loadItem(id) } ?: return Text("Entry not found.")
    var confirm by remember { mutableStateOf(false) }
    if (item.versions.size > 1) {
        Text("⚠ ${item.versions.size} conflicting versions from different devices.", color = MaterialTheme.colorScheme.error)
        Button(onClick = { go(Route.Resolve(id)) }) { Text("Resolve…") }
    }
    val v = item.versions.firstOrNull { it.entry != null } ?: return Text("All versions are deleted.")
    val e = v.entry!!
    Text(e.title, style = MaterialTheme.typography.headlineSmall)
    FieldRow("Username", e.username)
    FieldRow("Password", e.password, secret = true)
    e.urls.forEach { FieldRow("Website", it) }
    if (e.totp != null) TotpRow(id, v.index)
    e.customFields.forEach { FieldRow(it.name, it.value, secret = true) }
    if (e.notes.isNotEmpty()) FieldRow("Notes", e.notes)
    Row(horizontalArrangement = gap) {
        Button(onClick = { go(Route.Edit(id)) }) { Text("Edit") }
        OutlinedButton(onClick = { confirm = true }) { Text("Delete") }
    }
    if (confirm) AlertDialog(
        onDismissRequest = { confirm = false },
        title = { Text("Delete “${e.title}”?") },
        text = { Text("It is deleted on all your devices after they sync.") },
        confirmButton = { TextButton(onClick = { Vault.core.delete(id); Vault.edited(); home() }) { Text("Delete") } },
        dismissButton = { TextButton(onClick = { confirm = false }) { Text("Cancel") } },
    )
}

@Composable
fun TotpRow(id: String, index: UInt) {
    val c = LocalContext.current
    var code by remember { mutableStateOf("") }
    var left by remember { mutableStateOf(0uL) }
    LaunchedEffect(id, index) {
        while (true) {
            runCatching { Vault.core.totp(id, index) }.onSuccess { code = it.code; left = it.remaining }.onFailure { code = errMsg(it) }
            delay(1000)
        }
    }
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text("One-time code", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text("$code  (${left}s)", style = MaterialTheme.typography.titleLarge, fontFamily = FontFamily.Monospace)
        }
        TextButton(onClick = { Clipboard.copy(c, "TOTP", code) }) { Text("Copy") }
    }
}

private fun fieldsText(f: List<Field>) = f.joinToString("\n") { "${it.name}: ${it.value}" }
private fun parseFields(t: String) = t.lines().map { it.trim() }.filter { it.isNotEmpty() }.map {
    val i = it.indexOf(':')
    if (i < 0) Field(it, "") else Field(it.substring(0, i).trim(), it.substring(i + 1).trim())
}

@Composable
fun EditScreen(id: String?, done: (String) -> Unit) {
    val e = remember(id) { id?.let { loadItem(it) }?.versions?.firstOrNull { it.entry != null }?.entry }
    var title by remember { mutableStateOf(e?.title ?: "") }
    var user by remember { mutableStateOf(e?.username ?: "") }
    var pass by remember { mutableStateOf(e?.password ?: "") }
    var urls by remember { mutableStateOf(e?.urls?.joinToString("\n") ?: "") }
    var totp by remember { mutableStateOf(e?.totp ?: "") }
    var fields by remember { mutableStateOf(fieldsText(e?.customFields ?: emptyList())) }
    var notes by remember { mutableStateOf(e?.notes ?: "") }
    var showGen by remember { mutableStateOf(false) }
    var err by remember { mutableStateOf<String?>(null) }
    val scan = rememberLauncherForActivityResult(ScanContract()) { r -> r.contents?.let { totp = it } }

    OutlinedTextField(title, { title = it }, label = { Text("Title") }, singleLine = true, modifier = Modifier.fillMaxWidth())
    OutlinedTextField(user, { user = it }, label = { Text("Username") }, singleLine = true, modifier = Modifier.fillMaxWidth())
    PasswordField(pass, "Password") { pass = it }
    TextButton(onClick = { showGen = !showGen }) { Text(if (showGen) "Hide generator" else "Generate password") }
    if (showGen) Generator { pass = it; showGen = false }
    OutlinedTextField(urls, { urls = it }, label = { Text("Websites / apps (one per line, apps as androidapp://package)") }, modifier = Modifier.fillMaxWidth())
    Row(verticalAlignment = Alignment.CenterVertically) {
        OutlinedTextField(totp, { totp = it }, label = { Text("TOTP (otpauth:// or secret)") }, singleLine = true, modifier = Modifier.weight(1f))
        TextButton(onClick = { scan.launch(ScanOptions().setDesiredBarcodeFormats(ScanOptions.QR_CODE).setOrientationLocked(false).setBeepEnabled(false)) }) { Text("Scan") }
    }
    OutlinedTextField(fields, { fields = it }, label = { Text("Custom fields (name: value per line)") }, modifier = Modifier.fillMaxWidth())
    OutlinedTextField(notes, { notes = it }, label = { Text("Notes") }, modifier = Modifier.fillMaxWidth())
    ErrorText(err)
    Button(onClick = {
        val data = EntryData(
            title.trim(), user.trim(), pass, urls.lines().map { it.trim() }.filter { it.isNotEmpty() }, notes,
            totp.trim().ifEmpty { null }, parseFields(fields), 0L,
        )
        runCatching { Vault.core.put(id, data) }.onSuccess { Vault.edited(); done(it) }.onFailure { err = errMsg(it) }
    }) { Text("Save") }
}

/** Generator panel. With `use`, offers to put the password into the edit form. */
@Composable
fun Generator(use: ((String) -> Unit)?) {
    val c = LocalContext.current
    var len by remember { mutableStateOf(20f) }
    var lower by remember { mutableStateOf(true) }
    var upper by remember { mutableStateOf(true) }
    var digits by remember { mutableStateOf(true) }
    var symbols by remember { mutableStateOf(true) }
    var out by remember { mutableStateOf("") }
    fun gen() {
        out = runCatching { generatePassword(len.toUInt(), lower, upper, digits, symbols) }.getOrElse { errMsg(it) }
    }
    LaunchedEffect(len, lower, upper, digits, symbols) { gen() }
    Text("Length ${len.toInt()}")
    Slider(len, { len = it }, valueRange = 8f..64f, steps = 55)
    Row(verticalAlignment = Alignment.CenterVertically) {
        Checkbox(lower, { lower = it }); Text("a-z")
        Checkbox(upper, { upper = it }); Text("A-Z")
        Checkbox(digits, { digits = it }); Text("0-9")
        Checkbox(symbols, { symbols = it }); Text("!#$")
    }
    Text(out, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.titleMedium)
    Row(horizontalArrangement = gap) {
        OutlinedButton(onClick = ::gen) { Text("Regenerate") }
        OutlinedButton(onClick = { Clipboard.copy(c, "Password", out) }) { Text("Copy") }
        if (use != null) Button(onClick = { use(out) }) { Text("Use") }
    }
}

@Composable
fun ConflictsScreen(go: (Route) -> Unit) {
    val rev = Vault.rev
    val items = remember(rev) { runCatching { Vault.core.list() }.getOrDefault(emptyList()) }.filter { it.conflict }
    Text("These entries were changed on two devices before they synced. Pick a version or merge fields.")
    if (items.isEmpty()) Text("No conflicts.")
    items.forEach { s -> ListItem(headlineContent = { Text(s.title) }, modifier = Modifier.clickable { go(Route.Resolve(s.id)) }) }
}

private val FIELDS: List<Pair<String, (EntryData) -> String>> = listOf(
    "Title" to { it.title },
    "Username" to { it.username },
    "Password" to { it.password },
    "Websites" to { it.urls.joinToString("\n") },
    "TOTP" to { it.totp ?: "" },
    "Custom fields" to { fieldsText(it.customFields) },
    "Notes" to { it.notes },
)

/** Side-by-side versions; keep one, or pick each field and save the merge. */
@Composable
fun ResolveScreen(id: String, home: () -> Unit) {
    val item = remember { loadItem(id) } ?: return Text("Entry not found.")
    val live = item.versions.filter { it.entry != null }
    val pick = remember { mutableStateListOf(*Array(FIELDS.size) { 0 }) }
    fun save(e: EntryData) {
        Vault.core.put(id, e)
        Vault.edited()
        home()
    }
    Text("The result replaces all versions on every device.")
    Row(Modifier.fillMaxWidth(), horizontalArrangement = gap) {
        item.versions.forEach { v ->
            Column(Modifier.weight(1f)) {
                Text(v.label, style = MaterialTheme.typography.labelLarge)
                if (v.entry == null) OutlinedButton(onClick = { Vault.core.delete(id); Vault.edited(); home() }) { Text("Keep deletion") }
                else OutlinedButton(onClick = { save(v.entry!!) }) { Text("Keep this") }
            }
        }
    }
    if (live.size < 2) return
    HorizontalDivider()
    Text("Or merge field by field:", style = MaterialTheme.typography.titleMedium)
    FIELDS.forEachIndexed { fi, (name, get) ->
        Text(name, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Row(Modifier.fillMaxWidth()) {
            live.forEachIndexed { vi, v ->
                Row(Modifier.weight(1f).clickable { pick[fi] = vi }, verticalAlignment = Alignment.Top) {
                    RadioButton(pick[fi] == vi, { pick[fi] = vi })
                    Text(get(v.entry!!).ifEmpty { "—" }, Modifier.padding(top = 12.dp))
                }
            }
        }
    }
    Button(onClick = {
        val src = { fi: Int -> live[pick[fi]].entry!! }
        save(EntryData(src(0).title, src(1).username, src(2).password, src(3).urls, src(6).notes, src(4).totp, src(5).customFields, 0L))
    }) { Text("Save merged version") }
}
