//! Session establishment: authenticated hybrid prekey handshake.
//!
//! Replaces the former "X3DH" placeholder, which derived session keys from
//! PUBLIC data only (a complete confidentiality break). The real handshake:
//!
//! 1. The responder publishes a [`PrekeyBundle`]: identity keys
//!    (ML-DSA-65 + Ed25519 + X25519), a signed prekey (ML-KEM-768 + X25519)
//!    and a dual signature over the prekey.
//! 2. The initiator verifies the dual signature BEFORE any state change, then
//!    - encapsulates ML-KEM-768 against the responder's KEM prekey,
//!    - computes DH(ephemeral, responder prekey) and DH(ephemeral, responder identity),
//!    - derives the root secret via HKDF over (kem_ss || dh1 || dh2), bound to
//!      both identities and the handshake transcript.
//! 3. The responder recomputes the same secret from the [`HandshakeMessage`]
//!    and its own secret keys.
//!
//! Roles: the initiator drives [`Role::Initiator`] chains, the responder the
//! mirrored [`Role::Responder`] chains.

use crate::error::{KassiberError, Result};
use crate::keystore::AsyncKeystoreActor;
use crate::primitives::{
    hkdf32, AesAead, DualKeyPair, DualSignature, HybridKeyPair, PostQuantumPublicKey, X25519KeyPair,
};
use crate::ratchet::{RatchetConfig, Role, TripleRatchetAdapter};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;
use x25519_dalek::PublicKey as X25519PublicKey;

pub const WIRE_MESSAGE: u8 = 0x01;
pub const WIRE_PREKEY: u8 = 0x02;
pub const WIRE_REPLY: u8 = 0x03;
pub const WIRE_SESSION_RESET: u8 = 0x04;

#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub ratchet_config: RatchetConfig,
    pub max_skipped_messages: u32,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            ratchet_config: RatchetConfig::default(),
            max_skipped_messages: 1000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochCounter {
    value: u64,
    identity_key_binding: Vec<u8>,
}

impl EpochCounter {
    pub fn new(identity_key_binding: Vec<u8>) -> Self {
        Self {
            value: 0,
            identity_key_binding,
        }
    }

    pub fn increment(&mut self) -> u64 {
        self.value += 1;
        self.value
    }

    /// A remote epoch is acceptable for a session REFRESH (reset) only if it
    /// is strictly newer than what we have seen from this peer.
    pub fn validate_remote(&self, remote_epoch: u64) -> Result<()> {
        if remote_epoch <= self.value {
            Err(KassiberError::InvalidInput(format!(
                "Epoch counter {} not greater than {}",
                remote_epoch, self.value
            )))
        } else {
            Ok(())
        }
    }

    pub fn current(&self) -> u64 {
        self.value
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        postcard::to_allocvec(self)
            .map_err(|e| KassiberError::Serialization(format!("EpochCounter: {:?}", e)))
    }
}

/// Signed prekey bundle published by the responder.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrekeyBundle {
    /// ML-DSA-65 identity verifying key (FIPS 204).
    pub identity_ml_dsa: Vec<u8>,
    /// Ed25519 identity verifying key.
    pub identity_ed25519: Vec<u8>,
    /// X25519 identity key (for DH(ephemeral, identity)).
    pub identity_x25519: Vec<u8>,
    /// ML-KEM-768 encapsulation prekey.
    pub kem_prekey: Vec<u8>,
    /// X25519 signed prekey.
    pub x25519_prekey: Vec<u8>,
    /// postcard-serialized [`DualSignature`] over the prekey transcript.
    pub prekey_signature: Vec<u8>,
    pub epoch: u64,
}

impl PrekeyBundle {
    /// Transcript that is dual-signed: binds prekeys to identities and epoch.
    fn signature_transcript(&self) -> Vec<u8> {
        let mut t = Vec::new();
        t.extend_from_slice(b"kassiber-prekey-v1");
        t.extend_from_slice(&self.identity_ml_dsa);
        t.extend_from_slice(&self.identity_ed25519);
        t.extend_from_slice(&self.identity_x25519);
        t.extend_from_slice(&self.kem_prekey);
        t.extend_from_slice(&self.x25519_prekey);
        t.extend_from_slice(&self.epoch.to_le_bytes());
        t
    }
}

/// Initiator -> responder handshake message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeMessage {
    /// ML-KEM-768 ciphertext against the responder's KEM prekey.
    pub kem_ct: Vec<u8>,
    /// Initiator's ephemeral X25519 public key.
    pub ephemeral_x25519: Vec<u8>,
    /// Initiator's Ed25519 identity key (for transcript binding).
    pub initiator_identity: Vec<u8>,
    pub initiator_epoch: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionReset {
    pub new_bundle: PrekeyBundle,
    /// postcard-serialized [`DualSignature`] over the reset transcript.
    pub dual_signature: Vec<u8>,
    pub epoch_counter: u64,
}

#[derive(Debug)]
pub enum SessionState {
    Uninitialized,
    Handshaking,
    Established,
    NeedsReset,
}

#[derive(Debug)]
pub struct DecryptResult {
    pub plaintext: Vec<u8>,
    pub message_counter: u32,
}

pub struct KassiberSession {
    state: SessionState,
    config: SessionConfig,
    identity_key: Option<DualKeyPair>,
    /// X25519 identity key (signature identities cannot do DH).
    identity_dh: Option<X25519KeyPair>,
    /// Our current signed prekey pair (secret parts stay local).
    signed_prekey: Option<HybridKeyPair>,
    ratchet: Option<Mutex<TripleRatchetAdapter>>,
    /// Keystore handle for identity/prekey persistence. Currently only held
    /// for lifetime management; persistence wiring lands with the FFI phase.
    #[allow(dead_code)]
    keystore: Arc<AsyncKeystoreActor>,
    epoch_counter: Mutex<EpochCounter>,
    peer_identity: Option<Vec<u8>>,
    /// Highest epoch we have accepted from the peer.
    peer_epoch: Option<u64>,
}

impl KassiberSession {
    pub fn new(keystore: Arc<AsyncKeystoreActor>, config: SessionConfig) -> Self {
        let epoch = EpochCounter::new(vec![]);
        Self {
            state: SessionState::Uninitialized,
            config,
            identity_key: None,
            identity_dh: None,
            signed_prekey: None,
            ratchet: None,
            keystore,
            epoch_counter: Mutex::new(epoch),
            peer_identity: None,
            peer_epoch: None,
        }
    }

    pub async fn initialize(&mut self) -> Result<()> {
        let mut rng = rand::rng();
        let ik = DualKeyPair::generate(&mut rng)?;
        let identity_dh = X25519KeyPair::generate(&mut rng);
        let (_, ik_pub_bytes) = ik.verifying_keys();
        let epoch = EpochCounter::new(ik_pub_bytes.to_vec());
        self.identity_key = Some(ik);
        self.identity_dh = Some(identity_dh);
        *self.epoch_counter.lock().await = epoch;
        self.state = SessionState::Handshaking;
        log::info!("KassiberSession initialized");
        Ok(())
    }

    /// Generate (and locally store) a fresh signed prekey bundle.
    pub async fn generate_prekey_bundle(&mut self) -> Result<PrekeyBundle> {
        let mut rng = rand::rng();
        let ik = self
            .identity_key
            .as_ref()
            .ok_or_else(|| KassiberError::InvalidSession("No identity key".into()))?;
        let identity_dh = self
            .identity_dh
            .as_ref()
            .ok_or_else(|| KassiberError::InvalidSession("No identity key".into()))?;
        let prekey = HybridKeyPair::generate(&mut rng)?;
        let (identity_ml_dsa, identity_ed25519) = ik.verifying_keys();
        let epoch = self.epoch_counter.lock().await.current();
        let mut bundle = PrekeyBundle {
            identity_ml_dsa,
            identity_ed25519: identity_ed25519.to_vec(),
            identity_x25519: identity_dh.public.to_vec(),
            kem_prekey: prekey.pq.public.clone(),
            x25519_prekey: prekey.classical.public.to_vec(),
            prekey_signature: Vec::new(),
            epoch,
        };
        let signature = ik.sign(&bundle.signature_transcript())?;
        bundle.prekey_signature = postcard::to_allocvec(&signature)
            .map_err(|e| KassiberError::Serialization(format!("DualSignature: {:?}", e)))?;
        self.signed_prekey = Some(prekey);
        Ok(bundle)
    }

    /// Verify a bundle's dual signature. No state is touched on failure.
    fn verify_bundle(bundle: &PrekeyBundle) -> Result<()> {
        let sig: DualSignature = postcard::from_bytes(&bundle.prekey_signature)
            .map_err(|_| KassiberError::SignatureVerification)?;
        sig.verify(
            &bundle.signature_transcript(),
            &bundle.identity_ml_dsa,
            &bundle.identity_ed25519,
        )
    }

    /// Initiator side: verify the peer's bundle, run the hybrid handshake and
    /// return the [`HandshakeMessage`] to send to the responder.
    pub async fn process_prekey_bundle(&mut self, bundle: &PrekeyBundle) -> Result<HandshakeMessage> {
        // 1. Signature verification BEFORE any state change.
        Self::verify_bundle(bundle)?;

        // 2. Epoch monotonicity: re-handshakes at the same epoch are allowed,
        //    older epochs are not.
        if let Some(peer_epoch) = self.peer_epoch {
            if bundle.epoch < peer_epoch {
                return Err(KassiberError::InvalidInput(format!(
                    "Stale bundle epoch {} (have {})",
                    bundle.epoch, peer_epoch
                )));
            }
        }

        // 3. Hybrid handshake.
        let mut rng = rand::rng();
        let kem_pk = PostQuantumPublicKey {
            bytes: bundle.kem_prekey.clone(),
        };
        let (kem_ss, kem_ct) = kem_pk.encapsulate(&mut rng)?;
        let ephemeral = X25519KeyPair::generate(&mut rng);
        let peer_prekey_x = x25519_pub(&bundle.x25519_prekey)?;
        let peer_identity_x = x25519_pub(&bundle.identity_x25519)?;
        let dh1 = ephemeral.secret.diffie_hellman(&peer_prekey_x);
        let dh2 = ephemeral.secret.diffie_hellman(&peer_identity_x);

        let own_id_ed = self.own_identity_ed()?;
        let root = derive_handshake_root(
            &kem_ss,
            dh1.as_bytes(),
            dh2.as_bytes(),
            &own_id_ed,
            &bundle.identity_ed25519,
        );

        // 4. Only now mutate state.
        let mut ratchet_config = self.config.ratchet_config.clone();
        ratchet_config.max_skipped_keys = self.config.max_skipped_messages;
        let ratchet = TripleRatchetAdapter::new(&root, ratchet_config, Role::Initiator)?;
        self.ratchet = Some(Mutex::new(ratchet));
        self.peer_identity = Some(bundle.identity_ed25519.clone());
        self.peer_epoch = Some(bundle.epoch);
        self.state = SessionState::Established;
        let own_epoch = self.epoch_counter.lock().await.current();
        log::info!("Prekey bundle processed, session established (initiator)");
        Ok(HandshakeMessage {
            kem_ct,
            ephemeral_x25519: ephemeral.public.to_vec(),
            initiator_identity: own_id_ed.to_vec(),
            initiator_epoch: own_epoch,
        })
    }

    /// Responder side: complete the handshake using our stored prekey secrets.
    pub async fn accept_handshake(&mut self, msg: &HandshakeMessage) -> Result<()> {
        let prekey = self
            .signed_prekey
            .as_ref()
            .ok_or_else(|| KassiberError::InvalidSession("No signed prekey stored".into()))?;
        let identity_dh = self
            .identity_dh
            .as_ref()
            .ok_or_else(|| KassiberError::InvalidSession("No identity key".into()))?;

        let kem_ss = prekey.pq.decapsulate(&msg.kem_ct)?;
        let eph_pub = x25519_pub(&msg.ephemeral_x25519)?;
        let dh1 = prekey.classical.secret.diffie_hellman(&eph_pub);
        let dh2 = identity_dh.secret.diffie_hellman(&eph_pub);

        let own_id_ed = self.own_identity_ed()?;
        let root = derive_handshake_root(
            &kem_ss,
            dh1.as_bytes(),
            dh2.as_bytes(),
            &msg.initiator_identity,
            &own_id_ed,
        );

        let mut ratchet_config = self.config.ratchet_config.clone();
        ratchet_config.max_skipped_keys = self.config.max_skipped_messages;
        let ratchet = TripleRatchetAdapter::new(&root, ratchet_config, Role::Responder)?;
        self.ratchet = Some(Mutex::new(ratchet));
        self.peer_identity = Some(msg.initiator_identity.clone());
        self.peer_epoch = Some(msg.initiator_epoch);
        self.state = SessionState::Established;
        log::info!("Handshake accepted, session established (responder)");
        Ok(())
    }

    /// Own Ed25519 identity verifying key.
    fn own_identity_ed(&self) -> Result<[u8; 32]> {
        let ik = self
            .identity_key
            .as_ref()
            .ok_or_else(|| KassiberError::InvalidSession("No identity key".into()))?;
        Ok(ik.verifying_keys().1)
    }

    pub async fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<(AesAead, u32)> {
        match &self.ratchet {
            Some(ratchet) => {
                let mut guard = ratchet.lock().await;
                guard.encrypt(plaintext, aad)
            }
            None => Err(KassiberError::InvalidSession("Session not established".into())),
        }
    }

    pub async fn decrypt(&self, counter: u32, aead: &AesAead, aad: &[u8]) -> Result<DecryptResult> {
        match &self.ratchet {
            Some(ratchet) => {
                let mut guard = ratchet.lock().await;
                let plaintext = guard.decrypt(counter, aead, aad)?;
                Ok(DecryptResult {
                    plaintext,
                    message_counter: counter,
                })
            }
            None => Err(KassiberError::InvalidSession("Session not established".into())),
        }
    }

    /// Initiate a session refresh: publish a new signed bundle and sign the
    /// reset transcript. The session goes back to `Handshaking` until the peer
    /// answers with a [`HandshakeMessage`].
    pub async fn initiate_reset(&mut self) -> Result<SessionReset> {
        if self.identity_key.is_none() {
            return Err(KassiberError::InvalidSession("No identity key".into()));
        }
        let new_epoch = {
            let mut epoch = self.epoch_counter.lock().await;
            epoch.increment()
        };
        let new_bundle = self.generate_prekey_bundle().await?;
        let mut transcript = Vec::new();
        transcript.extend_from_slice(b"kassiber-reset-v1");
        transcript.extend_from_slice(
            &postcard::to_allocvec(&new_bundle)
                .map_err(|e| KassiberError::Serialization(format!("Bundle: {:?}", e)))?,
        );
        transcript.extend_from_slice(&new_epoch.to_le_bytes());
        let dual_sig = self
            .identity_key
            .as_ref()
            .expect("identity key checked above")
            .sign(&transcript)?;
        self.ratchet = None;
        self.state = SessionState::Handshaking;
        log::info!("Session reset initiated, epoch: {}", new_epoch);
        Ok(SessionReset {
            new_bundle,
            dual_signature: postcard::to_allocvec(&dual_sig)
                .map_err(|e| KassiberError::Serialization(format!("DualSignature: {:?}", e)))?,
            epoch_counter: new_epoch,
        })
    }

    /// Apply a peer's session reset: verify the reset signature and epoch,
    /// then process the new bundle like a fresh handshake.
    pub async fn apply_reset(&mut self, reset: &SessionReset) -> Result<HandshakeMessage> {
        // 1. Epoch must be strictly newer than anything seen from this peer.
        if let Some(peer_epoch) = self.peer_epoch {
            if reset.epoch_counter <= peer_epoch {
                return Err(KassiberError::InvalidInput(format!(
                    "Reset epoch {} not newer than {}",
                    reset.epoch_counter, peer_epoch
                )));
            }
        }
        if reset.new_bundle.epoch != reset.epoch_counter {
            return Err(KassiberError::InvalidInput(
                "Reset epoch does not match bundle epoch".into(),
            ));
        }

        // 2. Verify the reset dual signature over the exact transcript.
        let sig: DualSignature = postcard::from_bytes(&reset.dual_signature)
            .map_err(|_| KassiberError::SignatureVerification)?;
        let mut transcript = Vec::new();
        transcript.extend_from_slice(b"kassiber-reset-v1");
        transcript.extend_from_slice(
            &postcard::to_allocvec(&reset.new_bundle)
                .map_err(|e| KassiberError::Serialization(format!("Bundle: {:?}", e)))?,
        );
        transcript.extend_from_slice(&reset.epoch_counter.to_le_bytes());
        sig.verify(
            &transcript,
            &reset.new_bundle.identity_ml_dsa,
            &reset.new_bundle.identity_ed25519,
        )?;

        // 3. If we know this peer, the reset must come from the same identity.
        if let Some(peer_identity) = &self.peer_identity {
            if *peer_identity != reset.new_bundle.identity_ed25519 {
                return Err(KassiberError::SignatureVerification);
            }
        }

        // 4. Process the bundle (verifies the prekey signature again and
        //    establishes the new ratchet).
        self.process_prekey_bundle(&reset.new_bundle).await
    }

    pub fn needs_reset(&self) -> bool {
        matches!(self.state, SessionState::NeedsReset)
    }

    pub fn state(&self) -> &SessionState {
        &self.state
    }
}

/// HKDF root derivation for the handshake, bound to both identities.
fn derive_handshake_root(
    kem_ss: &[u8],
    dh1: &[u8],
    dh2: &[u8],
    initiator_identity: &[u8],
    responder_identity: &[u8],
) -> [u8; 32] {
    let mut ikm = Vec::with_capacity(kem_ss.len() + dh1.len() + dh2.len());
    ikm.extend_from_slice(kem_ss);
    ikm.extend_from_slice(dh1);
    ikm.extend_from_slice(dh2);
    let mut info = Vec::new();
    info.extend_from_slice(b"kassiber-handshake-v1");
    info.extend_from_slice(initiator_identity);
    info.extend_from_slice(responder_identity);
    hkdf32(&ikm, b"kassiber-handshake-salt-v1", &info)
}

fn x25519_pub(bytes: &[u8]) -> Result<X25519PublicKey> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| KassiberError::InvalidInput("X25519 key must be 32 bytes".into()))?;
    Ok(X25519PublicKey::from(arr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::KeystoreConfig;

    fn new_session() -> KassiberSession {
        let keystore = Arc::new(AsyncKeystoreActor::start(KeystoreConfig::default()));
        KassiberSession::new(keystore, SessionConfig::default())
    }

    async fn establish() -> (KassiberSession, KassiberSession) {
        let mut alice = new_session();
        let mut bob = new_session();
        alice.initialize().await.unwrap();
        bob.initialize().await.unwrap();
        let bob_bundle = bob.generate_prekey_bundle().await.unwrap();
        let hs = alice.process_prekey_bundle(&bob_bundle).await.unwrap();
        bob.accept_handshake(&hs).await.unwrap();
        (alice, bob)
    }

    #[tokio::test]
    async fn test_hybrid_handshake_two_party() {
        let (alice, bob) = establish().await;
        assert!(matches!(alice.state(), SessionState::Established));
        assert!(matches!(bob.state(), SessionState::Established));
        // Alice -> Bob
        let (ct, counter) = alice.encrypt(b"hello bob", b"aad").await.unwrap();
        let res = bob.decrypt(counter, &ct, b"aad").await.unwrap();
        assert_eq!(res.plaintext, b"hello bob");
        // Bob -> Alice (mirrored chains)
        let (ct2, counter2) = bob.encrypt(b"hello alice", b"aad").await.unwrap();
        let res2 = alice.decrypt(counter2, &ct2, b"aad").await.unwrap();
        assert_eq!(res2.plaintext, b"hello alice");
    }

    #[tokio::test]
    async fn test_mitm_tampered_bundle_rejected() {
        let mut alice = new_session();
        let mut bob = new_session();
        alice.initialize().await.unwrap();
        bob.initialize().await.unwrap();
        let bundle = bob.generate_prekey_bundle().await.unwrap();

        // Tamper with the KEM prekey: signature verification must fail.
        let mut evil = bundle.clone();
        evil.kem_prekey[0] ^= 0x01;
        assert!(alice.process_prekey_bundle(&evil).await.is_err());
        assert!(!matches!(alice.state(), SessionState::Established));

        // Tamper with the signature itself.
        let mut evil2 = bundle.clone();
        let last = evil2.prekey_signature.len() - 1;
        evil2.prekey_signature[last] ^= 0x01;
        assert!(alice.process_prekey_bundle(&evil2).await.is_err());

        // Swap in a completely different identity's signature material.
        let mut mallory = new_session();
        mallory.initialize().await.unwrap();
        let mallory_bundle = mallory.generate_prekey_bundle().await.unwrap();
        let mut evil3 = bundle.clone();
        evil3.prekey_signature = mallory_bundle.prekey_signature;
        assert!(alice.process_prekey_bundle(&evil3).await.is_err());

        // The untampered bundle still works (no state was poisoned).
        let hs = alice.process_prekey_bundle(&bundle).await.unwrap();
        bob.accept_handshake(&hs).await.unwrap();
    }

    #[tokio::test]
    async fn test_session_reset_flow() {
        let (mut alice, mut bob) = establish().await;
        // Alice refreshes; Bob verifies and answers; Alice completes.
        let reset = alice.initiate_reset().await.unwrap();
        assert!(matches!(alice.state(), SessionState::Handshaking));
        let hs = bob.apply_reset(&reset).await.unwrap();
        alice.accept_handshake(&hs).await.unwrap();
        assert!(matches!(alice.state(), SessionState::Established));

        let (ct, counter) = alice.encrypt(b"after reset", b"aad").await.unwrap();
        let res = bob.decrypt(counter, &ct, b"aad").await.unwrap();
        assert_eq!(res.plaintext, b"after reset");

        // Replay of the same reset must be rejected (stale epoch).
        assert!(bob.apply_reset(&reset).await.is_err());
    }

    #[tokio::test]
    async fn test_forged_reset_rejected() {
        let (mut alice, mut bob) = establish().await;
        let reset = alice.initiate_reset().await.unwrap();
        // Forgery: valid bundle, but flip the reset signature.
        let mut forged = reset.clone();
        let last = forged.dual_signature.len() - 1;
        forged.dual_signature[last] ^= 0x01;
        assert!(bob.apply_reset(&forged).await.is_err());
        // The genuine reset is still applicable afterwards.
        let hs = bob.apply_reset(&reset).await.unwrap();
        alice.accept_handshake(&hs).await.unwrap();
    }

    #[tokio::test]
    async fn test_out_of_order_session_messages() {
        let (alice, bob) = establish().await;
        let (ct0, c0) = alice.encrypt(b"msg0", b"").await.unwrap();
        let (ct1, c1) = alice.encrypt(b"msg1", b"").await.unwrap();
        let (ct2, c2) = alice.encrypt(b"msg2", b"").await.unwrap();
        // Deliver 2, then 0, then 1.
        assert_eq!(bob.decrypt(c2, &ct2, b"").await.unwrap().plaintext, b"msg2");
        assert_eq!(bob.decrypt(c0, &ct0, b"").await.unwrap().plaintext, b"msg0");
        assert_eq!(bob.decrypt(c1, &ct1, b"").await.unwrap().plaintext, b"msg1");
    }
}
