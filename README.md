<pre align="center">
█▄▀ ▄▀█ █▀ █▀ █ █▄▄ █▀▀ █▀█
█ █ █▀█ ▄█ ▄█ █ █▄█ ██▄ █▀▄
</pre>

<p align="center" dir="auto">
  <strong><em>There is no server. There is no cloud. There is only the key you hold.</em></strong><br>
  <code>Post-Quantum · Messenger-Agnostic · Serverless · High-Assurance</code>
</p>

<p align="center" dir="auto">
  <a href="https://www.gnu.org/licenses/agpl-3.0" rel="nofollow"><img src="https://img.shields.io/badge/License-AGPL--3.0-purple.svg?style=flat-square&logo=gnu" alt="AGPL-3.0"></a>
  <a href="#-f-droid-exclusive"><img src="https://img.shields.io/badge/Distribution-F--Droid_Exclusive-2ea44f?style=flat-square&logo=android" alt="F-Droid"></a>
  <a href="#-architecture"><img src="https://img.shields.io/badge/Stack-Rust_+_Kotlin-000000?style=flat-square&logo=rust" alt="Rust + Kotlin"></a>
  <a href="#-post-quantum-cryptography"><img src="https://img.shields.io/badge/Crypto-PQC_(ML--KEM--768|ML--DSA--65)-ff6b6b?style=flat-square" alt="PQC"></a>
</p>

---

## What is KASSIBER?

**KASSIBER** is not a messenger. It is a cryptographic invisibility layer that sits *between* you and any messenger you already use.

Historically, a **Kassiber** is a secret message smuggled past guards and censorship — never going through central channels, never logged, never intercepted. This app resurrects that philosophy for the digital age to fight modern mass surveillance.

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
| **Key Extraction (Forensic)** | **StrongBox / Titan M2** — Hardware-bound keys, never leave the secure element. |
| **Metadata Analysis** | **Serverless architecture** — No routing logs, no contact graphs, no timing data. |
| **Protocol Downgrade** | **Hybrid ratchet** — SPQR + libsignal, dual-layer forward secrecy. |
| **App Tampering** | **F-Droid reproducible builds** + **AGPL-3.0** — Source is law. |

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
│ ├─ Hybrid Ratchet       → SPQR ⨂ libsignal                   │
│ ├─ Keystore Actor       → StrongBox / Titan M2               │
│ └─ Dictionary Codec     → Transport-agnostic encoding        │
└──────────────────────────────────────────────────────────────┘
