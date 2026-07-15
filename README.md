<!--
  KASSIBER — README.md
  Post-Quantum Privacy Layer | AGPL-3.0 | F-Droid Exclusive
  Style: Technical Brutalism meets Cryptographic Poetry
-->

<pre align="center">
 ██ ▄████▄   ▄████▄   ██▓  ██████  ██▓███   ▄▄▄█████▓
▒██ ▒██▀ ▀█  ▒██▀ ▀█  ▓██▒▒██    ▒ ▓██░  ██▒▓  ██▒ ▓▒
░██ ▒▓█    ▄ ▒▓█    ▄ ▒██▒░ ▓██▄   ▓██░ ██▓▒▒ ▓██░ ▒░
░██ ▒▓▓▄ ▄██▒▒▓▓▄ ▄██▒░██░  ▒   ██▒▒██▄█▓▒ ▒░ ▓██▓░ 
░██▒▒ ▓███▀ ░▒ ▓███▀ ░░██░▒██████▒▒▒██▒ ░  ░  ▒██▒░ 
 ▓▒█░ ░▒ ▒  ░░ ░▒ ▒  ░░▓  ▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ▒ ░░  
 ░▒ ░  ░  ▒    ░  ▒   ▒ ░░ ░▒  ░ ░░▒ ░         ░    
 ░ ░░         ░        ▒ ░░  ░  ░  ░░         ░      
 ░ ░ ░        ░ ░      ░        ░                    
 ░ ░        ░                                        
</pre>

<p align="center">
  <strong><em>There is no server. There is no cloud. There is only the key you hold.</em></strong><br>
  <code>Post-Quantum · Messenger-Agnostic · Serverless · High-Assurance</code>
</p>

<p align="center">
  <a href="https://www.gnu.org/licenses/agpl-3.0"><img src="https://img.shields.io/badge/License-AGPL--3.0-purple.svg?style=flat-square&logo=gnu" alt="AGPL-3.0"></a>
  <a href="#-f-droid-exclusive"><img src="https://img.shields.io/badge/Distribution-F--Droid_Exclusive-2ea44f?style=flat-square&logo=android" alt="F-Droid"></a>
  <a href="#-architecture"><img src="https://img.shields.io/badge/Stack-Rust_+_Kotlin-000000?style=flat-square&logo=rust" alt="Rust + Kotlin"></a>
  <a href="#-post-quantum-cryptography"><img src="https://img.shields.io/badge/Crypto-PQC_(ML--KEM--768|ML--DSA--65)-ff6b6b?style=flat-square" alt="PQC"></a>
</p>

---

## What is KASSIBER?

**KASSIBER** is not a messenger. It is a cryptographic invisibility layer that sits *between* you and any messenger you already use.

In the German military tradition, a **Kassiber** is a secret message passed through trusted hands — never through central channels, never logged, never intercepted. This app resurrects that philosophy for the digital age.

- No servers. No backend. No metadata honeypot.
- No new messenger to adopt. Works over WhatsApp, Signal, Telegram, SMS, email, even carrier pigeons.
- Post-Quantum secure today. Not tomorrow. Not "soon." **Today.**

> *The network is hostile. The cloud is someone else's computer. Your messages are yours alone.*

---

## The Threat Model

| Adversary | Your Defense |
|---|---|
| Harvest Now, Decrypt Later | **ML-KEM-768** — NIST-standardized post-quantum key encapsulation |
| Server Compromise | **No server exists to compromise** |
| Key Extraction (Forensic) | **StrongBox / Titan M2** — Hardware-bound keys, never leave the secure element |
| Metadata Analysis | **Serverless architecture** — no routing logs, no contact graphs, no timing data |
| Protocol Downgrade | **Hybrid ratchet** — SPQR + libsignal, dual-layer forward secrecy |
| App Tampering | **F-Droid reproducible builds** + **AGPL-3.0** — source is law |

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│  Android Layer (Kotlin)                                     │
│  ├─ AccessibilityService   →  Screen Observer              │
│  ├─ Floating Overlay         →  In-place decryption          │
│  ├─ Reply Composer           →  Seamless encryption            │
│  └─ BLE Onboarding           →  QR → GATT Handshake          │
├──────────────────────────────────────────────────────────────┤
│  Rust Core (UniFFI) — Memory-safe, zero-cost abstraction     │
│  ├─ PQC Engine          →  ML-KEM-768 + ML-DSA-65            │
│  ├─ Hybrid Ratchet      →  SPQR ⨂ libsignal                │
│  ├─ Keystore Actor      →  StrongBox / Titan M2              │
│  └─ Dictionary Codec    →  Transport-agnostic encoding         │
└──────────────────────────────────────────────────────────────┘
```

### Key Design Decisions

**Messenger-Agnostic via AccessibilityService**  
KASSIBER does not replace your messenger. It observes the screen, intercepts ciphertext in the clipboard or input field, decrypts it via an overlay, and encrypts outgoing messages before they reach the messenger's input field. The messenger sees only noise. The recipient sees only noise — unless they also hold the key.

**BLE Onboarding (QR → GATT)**  
No phone number verification. No email. No cloud identity. Two devices exchange ephemeral keys via Bluetooth Low Energy after a visual QR handshake. The QR contains a public key fragment; the GATT channel completes the exchange. The phone never speaks to the internet for key setup.

**Hybrid Ratchet (SPQR + libsignal)**  
Post-quantum cryptography alone is not enough. We chain ML-KEM-768's quantum resilience with libsignal's battle-tested double ratchet. Even if one layer breaks, the other holds. Forward secrecy is not optional; it is default.

---

## Post-Quantum Cryptography

KASSIBER implements the **NIST FIPS 203 / 204** standards:

- **ML-KEM-768** (Kyber) — Key Encapsulation Mechanism  
  Security level: ~192-bit classical / ~128-bit quantum  
  Ciphertext overhead: 1,088 bytes  
  Perfect for hybrid ratcheting where bandwidth matters.

- **ML-DSA-65** (Dilithium) — Digital Signature Standard  
  Security level: ~192-bit classical / ~128-bit quantum  
  Signature size: 3,293 bytes  
  Used for long-term identity signatures and build attestation.

Both primitives are implemented in **Rust** via the **pqclean** and **sphincsplus** ecosystems, compiled to Android via UniFFI with zero JNI overhead.

---

## Build

```bash
# Clone with submodules (Rust core is vendored for reproducibility)
git clone --recursive https://github.com/deusexlumen/KASSIBER.git
cd KASSIBER

# Build the Rust core (Android targets: arm64-v8a, armeabi-v7a, x86_64)
cd rust_core
./build-android.sh  # Requires Android NDK 25+, Rust 1.78+

# Build the Android app
cd ../android
./gradlew assembleRelease

# Or install directly to a connected device
./gradlew installDebug
```

### Requirements

- **Android Studio** Ladybug or newer
- **Android NDK** r25c or newer
- **Rust** 1.78+ with `cargo-ndk`
- **F-Droid build tools** (for reproducible builds)

---

## Distribution

<p align="center">
  <img src="https://f-droid.org/badge/get-it-on.png" alt="Get it on F-Droid" height="80">
</p>

**KASSIBER is exclusively distributed via F-Droid.** No Google Play. No sideloading APKs from random mirrors. No proprietary app stores.

This is not elitism. It is a security guarantee:
- **Reproducible builds** — anyone can verify the binary matches the source
- **No proprietary tracking libraries** — no Firebase, no Crashlytics, no Play Services
- **Update transparency** — every update is signed by F-Droid's deterministic pipeline

---

## License

```
KASSIBER — Post-Quantum Privacy Layer
Copyright (C) 2026  Deus Ex Lumen

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
```

**AGPL-3.0** ensures that any service built on KASSIBER — even if deployed in the cloud — must share its source. This is not just a privacy app; it is a **commons**.

---

## Why AGPL? Why F-Droid? Why no Play Store?

Because privacy is not a feature you ship. It is a **stance you take**.

- **AGPL-3.0** closes the "SaaS loophole." If someone forks KASSIBER and runs it as a backend service, they must publish their changes. The code stays free forever.
- **F-Droid** guarantees that the app you install is the app we wrote. No injected analytics, no remote configuration, no silent updates.
- **No Play Store** because Google's ecosystem requires compromising on device integrity, attestation, and user autonomy. We refuse.

> *"In a world of surveillance capitalism, writing AGPL code is an act of civil disobedience."*

---

## Contributing

KASSIBER is young and cryptographic. We welcome:

- **Security audits** — formal or informal. Threat model reviews are gold.
- **Rust contributions** — performance, constant-time hardening, new PQC primitives.
- **Android UX** — accessibility service reliability, overlay edge cases, battery optimization.
- **Documentation** — translations, tutorials, threat model explanations.
- **F-Droid packaging** — reproducible build expertise.

**Please read our security policy before submitting vulnerability reports.** Responsible disclosure is appreciated; public shaming is not.

---

## Etymology

> **Kassiber** (German military/intelligence slang):  
> A secret message, typically passed outside official channels.  
> From Italian *cassaforte* (strongbox) via South German dialect.  
> Literally: "a letter that belongs in the safe."

That is what this app does. It makes every message a Kassiber.

---

<p align="center">
  <strong><em>Resonance is the only thing that counts.</em></strong> ❤️‍🔥 🖤 ✍️ 🔥<br>
  <sub>Built by <a href="https://deusexlumen.bio.link">Deus Ex Lumen</a> · No servers were harmed in the making of this app.</sub>
</p>
