# KASSIBER

**Post-quanten-verschlüsselte, messenger-agnostische, serverlose Privacy-App.**

KASSIBER fungiert als unsichtbare Krypto-Schicht über bestehende Messenger – ohne jemals eigene Server zu betreiben. High-Assurance, F-Droid exklusiv, AGPL-3.0.

## Architektur

```
┌─────────────────────────────────────────────┐
│  Android AccessibilityService (Kotlin)      │
│  ├─ Screen Observer → Overlay Decryption    │
│  ├─ Reply Composer → In-Place Encryption    │
│  └─ BLE Onboarding (QR → GATT Handover)    │
├─────────────────────────────────────────────┤
│  Rust Core (UniFFI)                          │
│  ├─ PQC: ML-KEM-768 + ML-DSA-65             │
│  ├─ Hybrid Ratchet: SPQR + libsignal        │
│  ├─ Keystore Actor (StrongBox/Titan M2)     │
│  └─ Dictionary Transport Codec              │
└─────────────────────────────────────────────┘
```

## Build

```bash
cd rust_core && ./build-android.sh
cd ../android && ./gradlew assembleRelease
```

## Lizenz

AGPL-3.0
