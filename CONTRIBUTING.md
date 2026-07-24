# Contributing to KASSIBER

KASSIBER is young and cryptographic. Contributions are welcome — but the bar
for crypto code is high. Read [SECURITY.md](SECURITY.md) before reporting
vulnerabilities (privately, not as public issues).

## Repository layout

```text
rust_core/                 Rust workspace — all cryptography lives here
├── kassiber-crypto/       ML-KEM-768 / ML-DSA-65, handshake, ratchet, keystore
├── kassiber-transport/    Dictionary codec, transport-agnostic encoding
├── kassiber-ffi/          UniFFI 0.29 surface exposed to Android
└── build-android.sh       Builds .so per ABI + regenerates Kotlin bindings
android/                   Kotlin app (AccessibilityService, overlay, BLE onboarding)
└── app/src/main/java/com/kassiber/ffi/   Generated UniFFI bindings (checked in)
```

## Build & test

```shell
# Rust core — run the full test suite (must stay green)
cd rust_core
cargo test --workspace

# Native libraries + UniFFI Kotlin bindings
# Requires Android NDK (r26+); adjust the NDK path in build-android.sh.
./build-android.sh
# Re-run whenever the FFI surface in kassiber-ffi changes, then commit the
# regenerated bindings under android/app/src/main/java/com/kassiber/ffi/.

# Android app
cd android
./gradlew assembleDebug
```

Requirements: Rust 1.80+, `cargo-ndk`, Android Studio Ladybug+, Android NDK r26+.

## Ground rules

- **No fakes, no placeholders in crypto paths.** No mock keys, no "TODO: real
  crypto", no stubbed verification. If a feature is not implemented, say so in
  the docs — never pretend in code.
- **Tests are mandatory for crypto changes.** Any change to handshake, ratchet,
  codec, or key handling must ship with tests. `cargo test --workspace` must
  pass before you open a PR.
- **Keep the FFI surface minimal.** Every new exported function is attack
  surface and binding churn. Justify additions.
- **Documentation is part of the change.** If you change behavior, update
  README.md / SECURITY.md so the docs never claim more than the code does.

## What we especially need

- Security review of the handshake and ratchet composition.
- StrongBox / Titan M2 key binding for the Android keystore.
- On-device testing and AccessibilityService reliability work.
- F-Droid packaging and reproducible-build expertise.
