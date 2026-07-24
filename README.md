<pre align="center">
██   ██  █████  ███████  ███████ ██ ██████  ███████ ██████  
██  ██  ██   ██ ██      ██       ██ ██   ██ ██      ██   ██ 
█████   ███████ ███████ ███████  ██ ██████  █████   ██████  
██  ██  ██   ██      ██      ██  ██ ██   ██ ██      ██   ██ 
██   ██ ██   ██ ███████ ███████  ██ ██████  ███████ ██   ██ 
</pre>

<p align="center" dir="auto">
  <strong><em>There is no server. There is no cloud. There is only the key you hold.</em></strong><br>
  <code>Post-Quantum · Messenger-Agnostic · Serverless · High-Assurance</code>
</p>

<p align="center" dir="auto">
  <a href="https://www.gnu.org/licenses/agpl-3.0" rel="nofollow"><img src="https://img.shields.io/badge/License-AGPL--3.0-purple.svg?style=flat-square&logo=gnu" alt="AGPL-3.0"></a>
  <a href="#distribution"><img src="https://img.shields.io/badge/Distribution-F--Droid_(planned)-2ea44f?style=flat-square&logo=android" alt="F-Droid planned"></a>
  <a href="#-architecture"><img src="https://img.shields.io/badge/Stack-Rust_+_Kotlin-000000?style=flat-square&logo=rust" alt="Rust + Kotlin"></a>
  <a href="#-post-quantum-cryptography"><img src="https://img.shields.io/badge/Crypto-PQC_(ML--KEM--768|ML--DSA--65)-ff6b6b?style=flat-square" alt="PQC"></a>
</p>

> ⚠️ **Disclaimer: Early Work in Progress (WIP)**  
> KASSIBER is currently in an early **experimental / pre-alpha stage**. It is a working proof-of-concept but has **not** been audited, and key features are still incomplete. **Do not use it for sensitive or productive communication.** Expect bugs and breaking changes. Active development, optimizations, and hardening are ongoing. Contributions and feedback are highly welcome!

---

## What is KASSIBER?

**KASSIBER** is not a messenger. It is a cryptographic invisibility layer that sits *between* you and any messenger you already use.

Historically, a **Kassiber** is a secret message smuggled past guards and censorship — never going through official channels, never logged, never intercepted. This app resurrects that philosophy for the digital age to fight modern mass surveillance (such as Client-Side Scanning).

* No servers. No backend. No metadata honeypot.
* No new messenger to adopt. Works over WhatsApp, Signal, Telegram, SMS, email, or even carrier pigeons.
* Post-Quantum secure today. Not tomorrow. Not "soon." **Today.**

> *The network is hostile. The cloud is someone else's computer. Your messages are yours alone.*

---

## The Threat Model

| Adversary | Your Defense |
| :--- | :--- |
| **Client-Side Scanning (CSS)** | **AccessibilityService Overlay** — The host messenger (and the OS scanner) only ever sees encrypted noise. |
| **Harvest Now, Decrypt Later** | **ML-KEM-768** — NIST-standardized post-quantum key encapsulation. |
| **Server Compromise** | **No server exists to compromise.** |
| **Key Extraction (Forensic)** | **Software keystore** — CSPRNG-generated keys, zeroized on drop. Hardware binding (StrongBox / Titan M2) is planned, not yet implemented. |
| **Metadata Analysis** | **Serverless architecture** — No routing logs, no contact graphs, no timing data. |
| **Protocol Downgrade** | **Hybrid handshake + ratchet** — ML-KEM-768 rekey alongside X25519, HKDF-bound to both identities. |
| **App Tampering** | **AGPL-3.0** — Source is law. F-Droid reproducible builds are planned. |

---

## Architecture

```text
┌──────────────────────────────────────────────────────────────┐
│ Android Layer (Kotlin)                                       │
│ ├─ AccessibilityService → Screen Observer                    │
│ ├─ Floating Overlay     → In-place decryption                │
│ ├─ Reply Composer       → Seamless encryption                │
│ └─ BLE Onboarding       → QR → GATT Handshake                │
├──────────────────────────────────────────────────────────────┤
│ Rust Core (UniFFI) — Memory-safe, zero-cost abstraction      │
│ ├─ PQC Engine           → ML-KEM-768 + ML-DSA-65             │
│ ├─ Ratchet & Session    → HKDF hash chains + ML-KEM rekey    │
│ ├─ Keystore             → Software CSPRNG + zeroize          │
│ └─ Dictionary Codec     → Transport-agnostic encoding        │
└──────────────────────────────────────────────────────────────┘
```

### Key Design Decisions

**Messenger-Agnostic via AccessibilityService**  
KASSIBER does not replace your messenger. It observes the screen, intercepts ciphertext in the clipboard or input field, decrypts it via a floating overlay, and encrypts outgoing messages before they reach the messenger's input field. The messenger sees only noise. The recipient sees only noise — unless they also hold the key.

**BLE Onboarding (QR → GATT)**  
No phone number verification. No email. No cloud identity. Two devices exchange ephemeral keys via Bluetooth Low Energy after a visual QR handshake. The QR contains a public key fragment; the GATT channel completes the exchange, bound to the QR via ephemeral X25519 + HKDF + AES-128-GCM. The phone never speaks to the internet for key setup.

**Hybrid Handshake + Hash-Chain Ratchet**  
Every session starts with a hybrid handshake: ML-KEM-768 encapsulation combined with X25519 DH (ephemeral ↔ prekey and ephemeral ↔ identity), mixed via HKDF and cryptographically bound to both identities. Prekey bundles are dual-signed (ML-DSA-65 + Ed25519) and verified *before* any state changes. The ratchet itself runs symmetric HKDF hash chains per direction with a skipped-key store for out-of-order messages; periodic ML-KEM rekeys refresh the chain. Forward secrecy comes from the KEM rekey and aggressive zeroization — long-term keys never touch message keys.

---

## Post-Quantum Cryptography

KASSIBER implements the **NIST FIPS 203 / 204** standards:

* **ML-KEM-768** (Kyber) — Key Encapsulation Mechanism  
  Security level: ~192-bit classical / ~128-bit quantum  
  Ciphertext overhead: 1,088 bytes  
  Perfect for hybrid ratcheting where bandwidth matters.

* **ML-DSA-65** (Dilithium) — Digital Signature Standard  
  Security level: ~192-bit classical / ~128-bit quantum  
  Signature size: 3,309 bytes  
  Used for long-term identity signatures and prekey bundle authentication.

Both primitives come from the **RustCrypto** ecosystem — [`ml-kem`](https://crates.io/crates/ml-kem) (FIPS 203) and [`ml-dsa`](https://crates.io/crates/ml-dsa) (FIPS 204) — alongside x25519-dalek, HKDF-SHA-256 and AES-256-GCM, compiled to Android via **UniFFI** (JNA-based bindings).

---

## Status

**Implemented:**

* Real PQC: ML-KEM-768 + ML-DSA-65 (RustCrypto), X25519, HKDF-SHA-256, AES-256-GCM with AAD, zeroize
* Hybrid handshake with dual-signed prekey bundles, verification before state change, signed session resets
* Hash-chain ratchet with skipped-key store and ML-KEM rekey
* Dictionary codec; UniFFI FFI surface with checked-in Kotlin bindings
* BLE onboarding crypto (GATT with encrypted characteristics, QR key binding)
* AccessibilityService overlay + reply injection
* `cargo test --workspace` green (40 tests), `assembleDebug` green

**In progress / planned:**

* Onboarding UI wiring (QR scan ↔ BLE ↔ `initiateSession` / `acceptSession`)
* BLE receiver-side decryption of sealed payloads
* StrongBox / Titan M2 hardware key binding
* Persistence of skipped ratchet keys across restarts
* On-device testing (`.so` build requires an Android NDK setup)
* F-Droid package (`com.kassiber.app`)
* Independent security audit

---

## Build

```shell
git clone https://github.com/deusexlumen/KASSIBER.git
cd KASSIBER

# Rust core — run the test suite
cd rust_core
cargo test --workspace

# Native libraries (arm64-v8a, armeabi-v7a, x86_64) + UniFFI Kotlin bindings
# Requires an Android NDK; the path is hardcoded in build-android.sh
# (currently ndk/26.1.10909125) — adjust it to your local install.
./build-android.sh

# Build the Android app
cd ../android
./gradlew assembleDebug

# Or install directly to a connected device
./gradlew installDebug
```

### Requirements
* **Android Studio** Ladybug or newer
* **Android NDK** r26+ (adjust the path in `build-android.sh`)
* **Rust** 1.80+ with `cargo-ndk`

---

## Distribution

**KASSIBER is planned to be distributed via F-Droid** (package id `com.kassiber.app`). The listing is not live yet — today, the only way to get KASSIBER is to build it from source. No Google Play. No sideloading APKs from random mirrors. No proprietary app stores.

This is not elitism. It is a security guarantee:

* **Reproducible builds** — anyone can verify the binary matches the source.
* **No proprietary tracking libraries** — no Firebase, no Crashlytics, no Play Services (ZXing instead of ML Kit for QR scanning).
* **Update transparency** — once listed, every update is signed by F-Droid's deterministic pipeline.

---

## License

```text
KASSIBER — Post-Quantum Privacy Layer
Copyright (C) 2026 Deus Ex Lumen

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
```

See [LICENSE](LICENSE) for the full text. **AGPL-3.0** ensures that any service built on KASSIBER — even if deployed in the cloud — must share its source. This is not just a privacy app; it is a **commons**.

---

## Why AGPL? Why F-Droid? Why no Play Store?

Because privacy is not a feature you ship. It is a **stance you take**.

* **AGPL-3.0** closes the "SaaS loophole." If someone forks KASSIBER and runs it as a backend service, they must publish their changes. The code stays free forever.
* **F-Droid** guarantees that the app you install is the app we wrote. No injected analytics, no remote configuration, no silent updates.
* **No Play Store** because Google's ecosystem requires compromising on device integrity, attestation, and user autonomy. We refuse.

> *"In a world of surveillance capitalism, writing AGPL code is an act of civil disobedience."*

---

## Contributing

KASSIBER is young and cryptographic. We welcome:
* **Security audits** — formal or informal. Threat model reviews are gold.
* **Rust contributions** — performance, constant-time hardening, new PQC primitives.
* **Android UX** — accessibility service reliability, overlay edge cases, battery optimization.
* **Documentation** — translations, tutorials, threat model explanations.
* **F-Droid packaging** — reproducible build expertise.

See [CONTRIBUTING.md](CONTRIBUTING.md) for build instructions and ground rules. **Please read our [security policy](SECURITY.md) before submitting vulnerability reports.** Responsible disclosure is appreciated; public shaming is not.

---

## Etymology

> **Kassiber** (German Rotwelsch / Prison slang):  
> A secret message smuggled past guards or censorship.  
> Originates from the Hebrew root *k-t-b* (to write) / *kesive* (document), which entered the German language via the historical secret language of vagabonds (Rotwelsch). It represents communication that evades systemic surveillance. 

That is what this app does. It makes every message a Kassiber.
