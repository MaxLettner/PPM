# peerpass

A local-first password manager that syncs directly between your own devices on the same
network. No server, no cloud, no relay.

- **Linux** (CachyOS/Arch, COSMIC/Wayland): `peerpassd` daemon (systemd user service) +
  GTK4/relm4 GUI + Firefox/Waterfox extension.
- **Android 13+**: Kotlin/Compose app with fingerprint unlock, AutofillService and
  background sync.
- One Rust core (`core/`) for model, crypto, storage, sync, pairing, TOTP, import and the
  password generator, shared by both platforms (Android via UniFFI).

```
core/          Rust lib: model, crypto, storage, sync, discovery, pairing, TOTP, import, generator
ffi/           UniFFI wrapper → Kotlin bindings (built with cargo-ndk)
linux/daemon/  peerpassd: owns DB + keys, runs sync, JSON-RPC on $XDG_RUNTIME_DIR/peerpass.sock
linux/gui/     relm4 app (thin client of the daemon)
linux/nmhost/  native-messaging host (browser ↔ daemon socket)
browser-ext/   WebExtension (MV3, Firefox/Waterfox)
android/       Compose app, AutofillService, SyncWorker
```

## How it works

- **Vault key** `K_v` (256-bit random). The synced **vault header** holds Argon2id
  parameters, salt and `K_v` wrapped with the key derived from your master password, so a
  password change on one device reaches the others.
- **Entries** are stored and synced as `XChaCha20-Poly1305(K_v, postcard(entry))` with
  AAD = `vault_id || entry_id`, plus a version vector. Sync only moves these opaque blobs,
  so it works while a device is locked.
- **Conflicts** (edits on two devices before they synced) keep both versions; the app
  shows a badge and a side-by-side view to keep one version or merge fields. An edit
  concurrent with a delete is a conflict too.
- **Transport**: every connection is a Noise session — `Noise_KK_25519_ChaChaPoly_BLAKE2s`
  between paired devices, `Noise_XKpsk3` (one-time QR token as PSK) for pairing. There is
  no unencrypted endpoint. Unknown devices are dropped before the handshake.
- **Discovery**: mDNS `_peerpass._tcp` (TXT `v=1`, `id=<device id>`) plus each peer's
  last known address, in case multicast is blocked.
- **Trust list**: paired devices are encrypted records inside the vault and sync like
  entries, so a device paired with A becomes trusted by B after B unlocks.

## Ports / firewall

| What | Port | Notes |
|---|---|---|
| Sync (TCP) | **47823** | `peerpassd --port N` to change; Android uses 47823 |
| mDNS (UDP) | **5353** | multicast 224.0.0.251; optional (last-address fallback) |

ufw on CachyOS (adjust the subnet to your LAN):

```bash
sudo ufw allow from 192.168.0.0/16 to any port 47823 proto tcp
```

```bash
sudo ufw allow from 192.168.0.0/16 to any port 5353 proto udp
```

## Build & install — Linux

Requirements: Rust (stable), `gtk4` (and `pkgconf`). On CachyOS: `sudo pacman -S gtk4 pkgconf`.

```bash
./linux/install.sh
```

This builds release binaries, installs `peerpassd`, `peerpass` (GUI) and `peerpass-nmhost`
to `~/.local/bin`, the systemd user unit, the `.desktop` file and the native-messaging
manifests, and enables the daemon (`systemctl --user enable --now peerpassd`).
Data lives in `~/.local/share/peerpass/` (`identity.key` and `peerpass.db`, mode 0600).

Run the tests:

```bash
cargo test --workspace
```

They include the 3-peer convergence property test, a raw-TCP capture asserting that no
title/username/password crosses the wire in plaintext, an mDNS discovery test, and an
end-to-end test with two `peerpassd` processes (different ports and DBs) that pair, sync,
conflict, delete and import.

## Build & install — Android

Requirements: Android SDK with platform 37 and NDK (r29 tested), JDK 17+, Rust targets
and cargo-ndk:

```bash
rustup target add aarch64-linux-android x86_64-linux-android
```

```bash
cargo install cargo-ndk
```

```bash
cd android && ANDROID_HOME=$HOME/Android/Sdk ./gradlew assembleRelease
```

Gradle runs `android/build-rust.sh` first (cargo-ndk for arm64-v8a + x86_64, then
UniFFI Kotlin bindings). The release APK is signed with the debug key for sideloading
(`app/build/outputs/apk/release/app-release.apk`); `adb install -r` it.

First start on the phone: create or join a vault, then the onboarding screen asks you to
1. turn off battery optimisation for peerpass,
2. allow auto-start (Doke OS kills background apps; if the button only opens App info,
   look for *Auto-start* / *Startup manager* there — the Doke OS screen could not be
   verified without the device),
3. pick peerpass as autofill service,
4. on Android 17+, allow local network access.

## Browser extension (Firefox / Waterfox)

The extension (`browser-ext/`, MV3) lists entries for the active tab's site (eTLD+1),
fills username + password **only when you click an entry**, and can copy a TOTP code. If
the vault is locked it shows "Unlock in peerpass". It talks to `peerpass-nmhost` via
native messaging; the host only allows `status`, `find` (no passwords), `fill` (one entry,
only if it belongs to the tab's site) and `totp`.

`install.sh` writes the host manifest `dev.peerpass.nmhost.json` to
`~/.mozilla/native-messaging-hosts/` and `~/.waterfox/native-messaging-hosts/`. Waterfox's
per-user path could not be verified here; if Waterfox does not find the host, copy the
manifest to the system-wide `/usr/lib/mozilla/native-messaging-hosts/`.

**Waterfox (primary, unsigned):**
1. `about:config` → `xpinstall.signatures.required` = `false`.
2. Build the package: `cd browser-ext && npx web-ext build` (or zip the folder's files).
3. `about:addons` → gear → *Install Add-on From File…* → the `.zip`/`.xpi`.

**Firefox release (needs a signature): AMO unlisted signing**
1. Create API credentials at addons.mozilla.org → Developer Hub → *Manage API Keys*.
2. `cd browser-ext && npx web-ext sign --channel=unlisted --api-key=$AMO_JWT_ISSUER --api-secret=$AMO_JWT_SECRET`
3. Install the signed `.xpi` from `web-ext-artifacts/`. (For quick tests,
   `about:debugging` → *Load Temporary Add-on* works until restart.)

## Threat model

**Protects against**
- A stolen or lost device without the master password: entries, trust list and `K_v` are
  encrypted at rest; `K_v` is only unwrapped with the Argon2id-derived key (or, on
  Android, a biometric-bound Keystore key).
- Passive and active attackers on the LAN: all traffic is inside authenticated Noise
  sessions; entries are additionally K_v-encrypted blobs.
- Unpaired devices: sync requires Noise_KK with a known static key; unknown device ids are
  dropped.
- A leaked pairing QR code: it is single-use, expires after 5 minutes, needs your accept
  on the existing device after comparing a 6-digit code, and the new device still needs
  the master password — the QR code alone never gives access to the vault.

**Does not protect against**
- Malware running as your user or as root on an unlocked device (it can talk to the daemon
  socket, read process memory or the clipboard).
- LAN observers learning that peerpass devices exist and their device ids (mDNS
  advertisements; the 8-byte device id is also sent in cleartext before the Noise handshake).
- Accepted metadata leak to paired peers and on disk: number of entries and edit counters.

## Known limitations (v1)

- Removing a device does not rotate `K_v`; the removed device keeps the data it had. Rotate
  by creating a new vault and re-importing if a device is lost *and* you fear the master
  password is known.
- Tombstones are never garbage-collected.
- Two devices changing the master password at the same moment: one header wins
  deterministically on all devices; use that password.
- Strings in the Kotlin UI and in JSON over the local socket cannot be zeroized; Rust-side
  secrets are zeroized (`zeroize`).
- The clipboard is cleared after 30 s by the Linux GUI and Android app; a TOTP code copied
  by the browser extension is not auto-cleared (the popup closes).
- KeePass import uses the `keepass` crate; files whose entries interleave `<String>` with
  other XML elements (unusual, not produced by KeePass/KeePassXC) fail to parse.
- Android mDNS uses the Rust `mdns-sd` crate under a `MulticastLock`. If discovery turns out
  unreliable on Doke OS, sync still works through each peer's last known address; an
  `NsdManager` fallback is not implemented yet.

## Manual test checklist (phone + laptop on the same Wi-Fi)

- [ ] **Pair**: laptop creates vault → Devices → *Pair new device*; phone scans QR (and
      once via pasted text); both show the same 6-digit code; accept on laptop; phone asks
      for the master password; entries appear on the phone.
- [ ] **Edit both while offline**: phone in airplane mode, edit different entries on both;
      reconnect; both converge within a minute (app open) or 15 min (app closed).
- [ ] **Conflict**: edit the *same* entry on both while offline; reconnect; conflict badge
      on both; resolve by merging fields on one device; badge disappears on both.
- [ ] **Delete**: delete on phone; gone on laptop after sync. Delete on one + edit on the
      other while offline → conflict showing "deleted" vs edited.
- [ ] **Background sync, app closed**: swipe the app away; edit on laptop; within ~15 min
      (Wi-Fi) the phone has it (open app in airplane mode to check).
- [ ] **Locked sync**: lock the phone app; edit on laptop; sync still happens; unlock shows it.
- [ ] **Master password change** on laptop → phone needs the new password; fingerprint
      unlock is turned off until the next password unlock.
- [ ] **Fingerprint**: enable after password unlock; unlock by fingerprint; enrol a new
      fingerprint → password required again.
- [ ] **Auto-lock**: 1 min setting locks after idle; screen off locks immediately.
- [ ] **Clipboard**: copied password disappears after 30 s; Android marks it sensitive.
- [ ] **Autofill**: login form in an app (entry with `androidapp://<package>`) and in
      Firefox for Android; locked vault shows "Unlock peerpass"; saving a new login offers
      to save.
- [ ] **Browser fill**: Waterfox popup lists entries for the site; click fills;
      "Unlock in peerpass" when locked; *Copy code* for TOTP.
- [ ] **Remove device**: remove the phone on the laptop; laptop no longer syncs with it.
- [ ] **Argon2 timing**: Android Settings → *Key derivation speed* → *Measure*; should be
      0.5–1 s. If not, adjust `KdfParams::default()` in `core/src/crypto.rs`.
- [ ] **Firewall**: with ufw enabled and the rules above, discovery and sync work.
