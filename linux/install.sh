#!/usr/bin/env bash
# Builds and installs peerpassd, the GUI and the native-messaging host for the current user.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build --release -p peerpassd -p peerpass-gui -p peerpass-nmhost
install -Dm755 target/release/peerpassd ~/.local/bin/peerpassd
install -Dm755 target/release/peerpass ~/.local/bin/peerpass
install -Dm755 target/release/peerpass-nmhost ~/.local/bin/peerpass-nmhost
install -Dm644 linux/dist/peerpassd.service ~/.config/systemd/user/peerpassd.service
install -Dm644 linux/dist/dev.peerpass.Peerpass.desktop ~/.local/share/applications/dev.peerpass.Peerpass.desktop
mkdir -p ~/.local/share/peerpass
# Native messaging manifests (Firefox, Waterfox).
host="$HOME/.local/bin/peerpass-nmhost"
for d in ~/.mozilla/native-messaging-hosts ~/.waterfox/native-messaging-hosts; do
  mkdir -p "$d"
  sed "s|@HOST_PATH@|$host|" browser-ext/peerpass.json.in > "$d/dev.peerpass.nmhost.json"
done
systemctl --user daemon-reload
systemctl --user enable --now peerpassd
echo "Installed. Open TCP port 47823 on your LAN (and UDP 5353 for mDNS), e.g.:"
echo "  sudo ufw allow from 192.168.0.0/16 to any port 47823 proto tcp"
echo "  sudo ufw allow from 192.168.0.0/16 to any port 5353 proto udp"
