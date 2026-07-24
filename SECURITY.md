# Security Policy

## Reporting a Vulnerability

Please report security vulnerabilities **privately** via
[GitHub Security Advisories](https://github.com/deusexlumen/KASSIBER/security/advisories/new)
for the `deusexlumen/KASSIBER` repository.

Do **not** open public issues for unpatched vulnerabilities. We will acknowledge
reports as quickly as possible, coordinate a fix, and credit reporters (unless
anonymity is preferred).

## Scope

In scope:

- The Rust core (`rust_core/`): key generation, handshake, ratchet, codec, FFI surface.
- The Android app (`android/`): keystore usage, BLE onboarding, AccessibilityService
  overlay and reply injection.
- The build and distribution pipeline (`rust_core/build-android.sh`, Gradle config).

Out of scope:

- Vulnerabilities in the host messengers KASSIBER runs on top of.
- Attacks requiring a fully compromised (rooted) device.
- Social engineering.

## Known Limitations (read before relying on this code)

KASSIBER is **pre-alpha** software. Concretely:

- **No independent security audit** has been performed. The cryptography is
  implemented from reputable RustCrypto crates, but the composition (handshake,
  ratchet, FFI boundary) has not been reviewed by a third party.
- **Hardware-backed keys are not implemented yet.** Keys live in a software
  keystore (CSPRNG-generated, zeroized on drop). StrongBox / Titan M2 binding
  is a design goal, not a current feature.
- **The ratchet does not persist skipped message keys** across restarts, so
  out-of-order delivery after a restart can fail.
- **Onboarding is not fully wired**: QR scan, BLE exchange and session setup
  are not yet connected end-to-end, and the BLE receiver side does not yet
  decrypt sealed payloads.
- **No on-device testing** has been done yet; the `.so` build for Android
  requires an NDK setup that has not run in CI.

**Do not use KASSIBER for sensitive or productive communication at this stage.**
It is a research prototype. If you need post-quantum-secure messaging today,
use an audited product.
