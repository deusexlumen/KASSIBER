//! Symmetric hash ratchet (HKDF chains) with an ML-KEM-768 based re-key step.
//!
//! This module previously claimed to wrap "SPQR + libsignal"; that was never
//! true (libsignal was an unused dependency). What is implemented here:
//!
//! - Per-direction HKDF chain keys, mirrored between the two roles so that
//!   Alice's send chain equals Bob's receive chain and vice versa.
//! - A skipped-message-key store for out-of-order delivery, bounded by
//!   `RatchetConfig::max_skipped_keys`.
//! - An optional ML-KEM-768 re-key: the sender encapsulates against the peer's
//!   current ratchet KEM key, both sides mix the shared secret into the root
//!   key and restart their chains.

use crate::error::{KassiberError, Result};
use crate::primitives::{hkdf32, Aes256GcmKey, AesAead, PostQuantumKeyPair, PostQuantumPublicKey};
use std::collections::HashMap;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Which side of the session this ratchet instance belongs to.
/// The two roles derive mirrored send/receive chains from the same root secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The party that processed the peer's prekey bundle (sent the handshake).
    Initiator,
    /// The party that published the prekey bundle (accepted the handshake).
    Responder,
}

#[derive(Debug, Clone)]
pub struct RatchetConfig {
    pub max_messages_per_phase: u32,
    pub max_lookahead: u32,
    pub rekey_interval_secs: u64,
    /// Upper bound for the skipped-message-key store (out-of-order receive).
    pub max_skipped_keys: u32,
}

impl Default for RatchetConfig {
    fn default() -> Self {
        Self {
            max_messages_per_phase: 1000,
            max_lookahead: 2000,
            rekey_interval_secs: 86400,
            max_skipped_keys: 1000,
        }
    }
}

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct SpqrRatchet {
    send_chain_key: Option<[u8; 32]>,
    recv_chain_key: Option<[u8; 32]>,
    root_key: [u8; 32],
    pub send_counter: u32,
    pub recv_counter: u32,
    /// Skipped message keys for out-of-order delivery, keyed by counter.
    /// Values are individually zeroized on drop/removal.
    #[zeroize(skip)]
    skipped_keys: HashMap<u32, Zeroizing<[u8; 32]>>,
    /// Our current ratchet KEM key pair; the peer encapsulates against the
    /// public part during a re-key.
    ratchet_kem: PostQuantumKeyPair,
    #[zeroize(skip)]
    role: Role,
    #[zeroize(skip)]
    config: RatchetConfig,
}

pub struct TripleRatchetAdapter {
    pub spqr: SpqrRatchet,
}

#[derive(Debug)]
pub struct RatchetStep {
    pub message_key: [u8; 32],
    pub next_chain_key: [u8; 32],
}

const INFO_CHAIN_A_TO_B: &[u8] = b"kassiber-chain-v1/initiator-to-responder";
const INFO_CHAIN_B_TO_A: &[u8] = b"kassiber-chain-v1/responder-to-initiator";
const INFO_ROOT: &[u8] = b"kassiber-ratchet-root-v1";
const INFO_MSG_KEY: &[u8] = b"kassiber-msg-key-v1";
const INFO_CHAIN_STEP: &[u8] = b"kassiber-chain-step-v1";
const INFO_REKEY_ROOT: &[u8] = b"kassiber-rekey-root-v1";

/// Derive the message key for `counter` from a chain key.
fn message_key(chain_key: &[u8; 32], counter: u32) -> [u8; 32] {
    hkdf32(chain_key, &counter.to_le_bytes(), INFO_MSG_KEY)
}

/// Advance a chain key by one step.
fn chain_step(chain_key: &[u8; 32]) -> [u8; 32] {
    hkdf32(chain_key, &[], INFO_CHAIN_STEP)
}

impl SpqrRatchet {
    /// Initialize both chain keys from the session shared secret.
    ///
    /// Initiator and responder MUST derive mirrored chains, otherwise the two
    /// peers can never decrypt each other's messages.
    pub fn initialize(shared_secret: &[u8], config: RatchetConfig, role: Role) -> Result<Self> {
        let root_key = hkdf32(shared_secret, &[], INFO_ROOT);
        let (send_info, recv_info) = match role {
            Role::Initiator => (INFO_CHAIN_A_TO_B, INFO_CHAIN_B_TO_A),
            Role::Responder => (INFO_CHAIN_B_TO_A, INFO_CHAIN_A_TO_B),
        };
        let send_ck = hkdf32(&root_key, &[], send_info);
        let recv_ck = hkdf32(&root_key, &[], recv_info);
        let ratchet_kem = PostQuantumKeyPair::generate_ml_kem768(&mut rand::rng())?;
        Ok(Self {
            send_chain_key: Some(send_ck),
            recv_chain_key: Some(recv_ck),
            root_key,
            send_counter: 0,
            recv_counter: 0,
            skipped_keys: HashMap::new(),
            ratchet_kem,
            role,
            config,
        })
    }

    pub fn role(&self) -> Role {
        self.role
    }

    /// Public part of our current ratchet KEM key; send to the peer so it can
    /// trigger a re-key via [`SpqrRatchet::rekey_send`].
    pub fn ratchet_public_key(&self) -> &[u8] {
        &self.ratchet_kem.public
    }

    pub fn next_send_key(&mut self) -> Result<RatchetStep> {
        let ck = self
            .send_chain_key
            .ok_or_else(|| KassiberError::RatchetDesync("No send chain key".into()))?;
        if self.send_counter >= self.config.max_messages_per_phase {
            return Err(KassiberError::RatchetDesync(
                "Max messages per phase exceeded".into(),
            ));
        }
        let mk = message_key(&ck, self.send_counter);
        let next_ck = chain_step(&ck);
        self.send_chain_key = Some(next_ck);
        self.send_counter += 1;
        Ok(RatchetStep {
            message_key: mk,
            next_chain_key: next_ck,
        })
    }

    pub fn recv_key_at(&mut self, counter: u32) -> Result<RatchetStep> {
        // 1. Out-of-order delivery: a previously skipped key?
        if let Some(key) = self.skipped_keys.remove(&counter) {
            let current_ck = self
                .recv_chain_key
                .ok_or_else(|| KassiberError::RatchetDesync("No recv chain key".into()))?;
            return Ok(RatchetStep {
                message_key: *key,
                next_chain_key: current_ck,
            });
        }

        let mut current_ck = self
            .recv_chain_key
            .ok_or_else(|| KassiberError::RatchetDesync("No recv chain key".into()))?;

        // 2. Keys below the receive head are gone (already consumed and never
        //    stored as skipped — e.g. replay).
        if counter < self.recv_counter {
            return Err(KassiberError::RatchetDesync(format!(
                "Counter {} already consumed (head at {})",
                counter, self.recv_counter
            )));
        }
        if counter > self.recv_counter + self.config.max_lookahead {
            return Err(KassiberError::RatchetDesync(format!(
                "Counter {} too far ahead of {}",
                counter, self.recv_counter
            )));
        }

        // 3. Advance the chain, storing every skipped message key so
        //    out-of-order messages can still be decrypted later.
        while self.recv_counter < counter {
            let skipped = message_key(&current_ck, self.recv_counter);
            self.skipped_keys
                .insert(self.recv_counter, Zeroizing::new(skipped));
            // Bound the store: evict the oldest (lowest-counter) entry.
            if self.skipped_keys.len() as u32 > self.config.max_skipped_keys {
                if let Some(&oldest) = self.skipped_keys.keys().min() {
                    self.skipped_keys.remove(&oldest);
                }
            }
            current_ck = chain_step(&current_ck);
            self.recv_counter += 1;
        }

        let mk = message_key(&current_ck, counter);
        let next_ck = chain_step(&current_ck);
        self.recv_chain_key = Some(next_ck);
        self.recv_counter = counter + 1;
        Ok(RatchetStep {
            message_key: mk,
            next_chain_key: next_ck,
        })
    }

    /// Trigger a KEM re-key: encapsulate against the peer's current ratchet
    /// KEM key, mix the shared secret into the root key, restart our chains.
    /// Returns the ML-KEM ciphertext to transmit to the peer.
    pub fn rekey_send(&mut self, peer_ratchet_key: &[u8]) -> Result<Vec<u8>> {
        let peer_key = PostQuantumPublicKey {
            bytes: peer_ratchet_key.to_vec(),
        };
        let (shared, ct) = peer_key.encapsulate(&mut rand::rng())?;
        self.mix_rekey_secret(&shared);
        Ok(ct)
    }

    /// Complete a KEM re-key initiated by the peer: decapsulate, rotate our
    /// ratchet KEM key pair, mix the shared secret into the root key.
    /// Returns our NEW ratchet public key (send to the peer for future re-keys).
    pub fn rekey_recv(&mut self, kem_ct: &[u8]) -> Result<Vec<u8>> {
        let shared = self.ratchet_kem.decapsulate(kem_ct)?;
        // Rotate BEFORE mixing so a compromised old ratchet key cannot be
        // reused for the next round.
        self.ratchet_kem = PostQuantumKeyPair::generate_ml_kem768(&mut rand::rng())?;
        self.mix_rekey_secret(&shared);
        Ok(self.ratchet_kem.public.clone())
    }

    fn mix_rekey_secret(&mut self, shared: &[u8]) {
        self.root_key = hkdf32(shared, &self.root_key, INFO_REKEY_ROOT);
        let (send_info, recv_info) = match self.role {
            Role::Initiator => (INFO_CHAIN_A_TO_B, INFO_CHAIN_B_TO_A),
            Role::Responder => (INFO_CHAIN_B_TO_A, INFO_CHAIN_A_TO_B),
        };
        self.send_chain_key = Some(hkdf32(&self.root_key, &[], send_info));
        self.recv_chain_key = Some(hkdf32(&self.root_key, &[], recv_info));
        self.send_counter = 0;
        self.recv_counter = 0;
        self.skipped_keys.clear();
    }

    pub fn needs_rekey(&self) -> bool {
        self.send_counter >= self.config.max_messages_per_phase
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut state = Vec::new();
        state.extend_from_slice(&self.root_key);
        state.extend_from_slice(&self.send_counter.to_le_bytes());
        state.extend_from_slice(&self.recv_counter.to_le_bytes());
        state.push(self.role as u8);
        state
    }
}

impl TripleRatchetAdapter {
    pub fn new(shared_secret: &[u8], config: RatchetConfig, role: Role) -> Result<Self> {
        Ok(Self {
            spqr: SpqrRatchet::initialize(shared_secret, config, role)?,
        })
    }

    pub fn encrypt(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<(AesAead, u32)> {
        let step = self.spqr.next_send_key()?;
        let aes_key = Aes256GcmKey::from_shared_secret(&step.message_key);
        let ct = aes_key.encrypt(plaintext, aad)?;
        Ok((ct, self.spqr.send_counter - 1))
    }

    pub fn decrypt(&mut self, counter: u32, aead: &AesAead, aad: &[u8]) -> Result<Vec<u8>> {
        let step = self.spqr.recv_key_at(counter)?;
        let aes_key = Aes256GcmKey::from_shared_secret(&step.message_key);
        aes_key.decrypt(aead, aad)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alice_bob() -> (SpqrRatchet, SpqrRatchet) {
        let secret = b"test_shared_secret_32_bytes_long";
        let alice = SpqrRatchet::initialize(secret, RatchetConfig::default(), Role::Initiator).unwrap();
        let bob = SpqrRatchet::initialize(secret, RatchetConfig::default(), Role::Responder).unwrap();
        (alice, bob)
    }

    #[test]
    fn test_spqr_roundtrip() {
        let (mut alice, mut bob) = alice_bob();
        let step = alice.next_send_key().unwrap();
        let key1 = Aes256GcmKey::from_shared_secret(&step.message_key);
        let ct = key1.encrypt(b"hello", b"aad").unwrap();
        let recv_step = bob.recv_key_at(0).unwrap();
        let key2 = Aes256GcmKey::from_shared_secret(&recv_step.message_key);
        let pt = key2.decrypt(&ct, b"aad").unwrap();
        assert_eq!(pt, b"hello");
    }

    #[test]
    fn test_bidirectional() {
        let (mut alice, mut bob) = alice_bob();
        // Alice -> Bob
        let s1 = alice.next_send_key().unwrap();
        let r1 = bob.recv_key_at(0).unwrap();
        assert_eq!(s1.message_key, r1.message_key);
        // Bob -> Alice (mirrored chains must differ from the other direction)
        let s2 = bob.next_send_key().unwrap();
        let r2 = alice.recv_key_at(0).unwrap();
        assert_eq!(s2.message_key, r2.message_key);
        assert_ne!(s1.message_key, s2.message_key);
    }

    #[test]
    fn test_out_of_order_delivery() {
        let (mut alice, mut bob) = alice_bob();
        // Alice sends 0, 1, 2; Bob receives 2 first, then 0 and 1.
        let m0 = alice.next_send_key().unwrap();
        let m1 = alice.next_send_key().unwrap();
        let m2 = alice.next_send_key().unwrap();

        let r2 = bob.recv_key_at(2).unwrap();
        assert_eq!(r2.message_key, m2.message_key);
        let r0 = bob.recv_key_at(0).unwrap();
        assert_eq!(r0.message_key, m0.message_key);
        let r1 = bob.recv_key_at(1).unwrap();
        assert_eq!(r1.message_key, m1.message_key);

        // Replays are rejected: key 0 is consumed, key 3 was never skipped.
        assert!(bob.recv_key_at(0).is_err());
    }

    #[test]
    fn test_skipped_key_store_bound() {
        let secret = b"bound_test_secret_32_bytes_longg";
        let config = RatchetConfig {
            max_skipped_keys: 8,
            max_lookahead: 100,
            ..RatchetConfig::default()
        };
        let mut alice = SpqrRatchet::initialize(secret, config.clone(), Role::Initiator).unwrap();
        let mut bob = SpqrRatchet::initialize(secret, config, Role::Responder).unwrap();
        let m0 = alice.next_send_key().unwrap();
        let _m1 = alice.next_send_key().unwrap();
        // 18 more sends (counters 2..=19).
        let m_rest: Vec<_> = (0..18).map(|_| alice.next_send_key().unwrap()).collect();
        // Jump to 19: 19 skipped keys are derived, but the store is capped at 8.
        let r19 = bob.recv_key_at(19).unwrap();
        assert_eq!(r19.message_key, m_rest[17].message_key);
        // Key 0 (and everything below counter 11) was evicted.
        assert!(bob.recv_key_at(0).is_err());
        // A key inside the retained window still decrypts.
        let r15 = bob.recv_key_at(15).unwrap();
        assert_eq!(r15.message_key, m_rest[13].message_key);
        assert!(bob.skipped_keys.len() <= 8);
        let _ = m0;
    }

    #[test]
    fn test_kem_rekey_roundtrip() {
        let (mut alice, mut bob) = alice_bob();
        // Exchange some messages first.
        let _ = alice.next_send_key().unwrap();
        let _ = bob.recv_key_at(0).unwrap();

        // Alice re-keys against Bob's current ratchet KEM key.
        let bob_key = bob.ratchet_public_key().to_vec();
        let kem_ct = alice.rekey_send(&bob_key).unwrap();
        let bob_new_key = bob.rekey_recv(&kem_ct).unwrap();
        assert_ne!(bob_new_key, bob_key);

        // Chains are re-synchronized: both directions work again from 0.
        let s = alice.next_send_key().unwrap();
        let r = bob.recv_key_at(0).unwrap();
        assert_eq!(s.message_key, r.message_key);
        let s2 = bob.next_send_key().unwrap();
        let r2 = alice.recv_key_at(0).unwrap();
        assert_eq!(s2.message_key, r2.message_key);
    }

    #[test]
    fn test_triple_ratchet_adapter() {
        let secret = b"adapter_secret_32_bytes_longgg";
        let mut alice =
            TripleRatchetAdapter::new(secret, RatchetConfig::default(), Role::Initiator).unwrap();
        let mut bob =
            TripleRatchetAdapter::new(secret, RatchetConfig::default(), Role::Responder).unwrap();
        let (ct, counter) = alice.encrypt(b"test message", b"aad").unwrap();
        let pt = bob.decrypt(counter, &ct, b"aad").unwrap();
        assert_eq!(pt, b"test message");
        // Wrong AAD must fail end-to-end.
        let (ct2, counter2) = alice.encrypt(b"second", b"aad").unwrap();
        assert!(bob.decrypt(counter2, &ct2, b"wrong").is_err());
    }
}
