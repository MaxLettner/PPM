#!/usr/bin/env bash
# Cross-compiles peerpass-ffi for arm64-v8a (phone) and x86_64 (emulator) and generates
# the Kotlin bindings. Needs: rustup targets aarch64-linux-android x86_64-linux-android,
# cargo-ndk, and ANDROID_NDK_HOME (or an NDK under $ANDROID_HOME/ndk).
set -euo pipefail
cd "$(dirname "$0")"
ROOT=..
if [ -z "${ANDROID_NDK_HOME:-}" ]; then
  SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Android/Sdk}}"
  ANDROID_NDK_HOME="$(ls -d "$SDK"/ndk/* 2>/dev/null | sort -V | tail -1)"
  export ANDROID_NDK_HOME
fi
PROFILE="${PEERPASS_RUST_PROFILE:-release}"
( cd "$ROOT" && cargo ndk -t arm64-v8a -t x86_64 --platform 33 -o android/app/src/main/jniLibs \
    build --profile "$PROFILE" -p peerpass-ffi )
# Bindings come from an unstripped host build (release builds strip UniFFI metadata).
( cd "$ROOT" && cargo build -q -p peerpass-ffi --lib && cargo run -q -p peerpass-ffi --bin uniffi-bindgen -- generate \
    --library target/debug/libpeerpass_ffi.so \
    --language kotlin --out-dir android/app/src/main/java --no-format )
