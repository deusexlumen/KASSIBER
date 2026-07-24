//! KASSIBER Cryptographic Core
//!
//! Hybrid Post-Quantum + Classical cryptography:
//! - KEM: ML-KEM-768 (FIPS 203) + X25519
//! - Signatures: ML-DSA-65 (FIPS 204) + Ed25519 (dual signatures)
//! - AEAD: AES-256-GCM (with AAD)
//! - KDF: HKDF-SHA-256
//! - Ratchet: symmetric HKDF chain ratchet (role-mirrored chains, skipped-key
//!   store for out-of-order delivery) with ML-KEM-768 re-key
//! - Handshake: authenticated hybrid prekey handshake (ML-KEM + X25519,
//!   dual-signed prekey bundles)

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod error;
pub mod keystore;
pub mod primitives;
pub mod ratchet;
pub mod session;

pub use error::{KassiberError, Result};
pub use keystore::{AsyncKeystoreActor, KeystoreConfig, SecureKeyHandle};
pub use primitives::{
    Aes256GcmKey, AesAead, DualKeyPair, HybridCiphertext, HybridKeyPair, HybridPublicKey,
    HybridSecretKey, MlDsa65KeyPair, PostQuantumKeyPair, PostQuantumPublicKey, X25519KeyPair,
};
pub use ratchet::{RatchetConfig, Role, SpqrRatchet, TripleRatchetAdapter};
pub use session::{
    DecryptResult, EpochCounter, HandshakeMessage, KassiberSession, PrekeyBundle, SessionConfig,
    SessionReset, SessionState,
};
