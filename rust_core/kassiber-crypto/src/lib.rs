//! KASSIBER Cryptographic Core
//!
//! Hybrid Post-Quantum + Classical cryptography:
//! - KEM: ML-KEM-768 + X25519
//! - Signature: ML-DSA-65 + Ed25519
//! - AEAD: AES-256-GCM
//! - Ratchet: SPQR (v1.5.1) + libsignal Triple Ratchet

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
pub use ratchet::{RatchetConfig, SpqrRatchet, TripleRatchetAdapter};
pub use session::{
    DecryptResult, EpochCounter, KassiberSession, PrekeyBundle, SessionConfig, SessionReset,
    SessionState,
};
