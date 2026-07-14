use crate::error::{KassiberError, Result};
use crate::keystore::AsyncKeystoreActor;
use crate::primitives::{Aes256GcmKey, AesAead, DualKeyPair, HybridKeyPair};
use crate::ratchet::{RatchetConfig, TripleRatchetAdapter};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;

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
        Self { ratchet_config: RatchetConfig::default(), max_skipped_messages: 1000 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochCounter {
    value: u64,
    identity_key_binding: Vec<u8>,
}

impl EpochCounter {
    pub fn new(identity_key_binding: Vec<u8>) -> Self {
        Self { value: 0, identity_key_binding }
    }

    pub fn increment(&mut self) -> u64 {
        self.value += 1;
        self.value
    }

    pub fn validate_remote(&self, remote_epoch: u64) -> Result<()> {
        if remote_epoch <= self.value {
            Err(KassiberError::InvalidInput(format!("Epoch counter {} not greater than {}", remote_epoch, self.value)))
        } else {
            Ok(())
        }
    }

    pub fn current(&self) -> u64 { self.value }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        postcard::to_allocvec(self).map_err(|e| KassiberError::Serialization(format!("EpochCounter: {:?}", e)))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrekeyBundle {
    pub identity_key: Vec<u8>,
    pub signed_prekey: Vec<u8>,
    pub prekey_signature: Vec<u8>,
    pub one_time_prekeys: Vec<Vec<u8>>,
    pub epoch: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionReset {
    pub new_bundle: PrekeyBundle,
    pub sender_ik_pub: Vec<u8>,
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
    ratchet: Option<Mutex<TripleRatchetAdapter>>,
    keystore: Arc<AsyncKeystoreActor>,
    epoch_counter: Mutex<EpochCounter>,
    peer_identity: Option<Vec<u8>>,
}

impl KassiberSession {
    pub fn new(keystore: Arc<AsyncKeystoreActor>, config: SessionConfig) -> Self {
        let epoch = EpochCounter::new(vec![]);
        Self { state: SessionState::Uninitialized, config, identity_key: None, ratchet: None, keystore, epoch_counter: Mutex::new(epoch), peer_identity: None }
    }

    pub async fn initialize(&mut self) -> Result<()> {
        use rand::thread_rng;
        let mut rng = thread_rng();
        let ik = DualKeyPair::generate(&mut rng)?;
        let ik_pub_bytes = ik.ed25519.verifying_key().as_bytes().to_vec();
        let epoch = EpochCounter::new(ik_pub_bytes);
        self.identity_key = Some(ik);
        *self.epoch_counter.lock().await = epoch;
        self.state = SessionState::Handshaking;
        log::info!("KassiberSession initialized");
        Ok(())
    }

    pub async fn generate_prekey_bundle(&self) -> Result<PrekeyBundle> {
        use rand::thread_rng;
        let mut rng = thread_rng();
        let ik = self.identity_key.as_ref().ok_or_else(|| KassiberError::InvalidSession("No identity key".into()))?;
        let hybrid_kp = HybridKeyPair::generate(&mut rng)?;
        let ik_pub = ik.ed25519.verifying_key().as_bytes().to_vec();
        let prekey_bytes = hybrid_kp.public_key().pq_encap.bytes;
        let signature = ik.sign(&prekey_bytes)?;
        let epoch = self.epoch_counter.lock().await.current();
        Ok(PrekeyBundle { identity_key: ik_pub, signed_prekey: prekey_bytes, prekey_signature: signature.ed25519_sig.to_vec(), one_time_prekeys: vec![], epoch })
    }

    pub async fn process_prekey_bundle(&mut self, bundle: &PrekeyBundle) -> Result<()> {
        { let epoch = self.epoch_counter.lock().await; epoch.validate_remote(bundle.epoch)?; }
        self.peer_identity = Some(bundle.identity_key.clone());
        self.state = SessionState::Established;
        let dummy_secret = crate::primitives::concat_hash(&bundle.signed_prekey, b"x3dh-derivation");
        let ratchet = TripleRatchetAdapter::new(&dummy_secret, self.config.ratchet_config.clone());
        self.ratchet = Some(Mutex::new(ratchet));
        log::info!("Prekey bundle processed, session established");
        Ok(())
    }

    pub async fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<(AesAead, u32)> {
        match &self.ratchet {
            Some(ratchet) => { let mut guard = ratchet.lock().await; guard.encrypt(plaintext, aad) }
            None => Err(KassiberError::InvalidSession("Session not established".into())),
        }
    }

    pub async fn decrypt(&self, counter: u32, aead: &AesAead, aad: &[u8]) -> Result<DecryptResult> {
        match &self.ratchet {
            Some(ratchet) => {
                let mut guard = ratchet.lock().await;
                let plaintext = guard.decrypt(counter, aead, aad)?;
                Ok(DecryptResult { plaintext, message_counter: counter })
            }
            None => Err(KassiberError::InvalidSession("Session not established".into())),
        }
    }

    pub async fn initiate_reset(&mut self) -> Result<SessionReset> {
        let ik = self.identity_key.as_ref().ok_or_else(|| KassiberError::InvalidSession("No identity key".into()))?;
        let new_bundle = self.generate_prekey_bundle().await?;
        let new_epoch = { let mut epoch = self.epoch_counter.lock().await; epoch.increment() };
        let ik_pub = ik.ed25519.verifying_key().as_bytes().to_vec();
        let mut transcript = Vec::new();
        transcript.extend_from_slice(&ik_pub);
        transcript.extend_from_slice(&postcard::to_allocvec(&new_bundle).map_err(|e| KassiberError::Serialization(format!("Bundle: {:?}", e)))?);
        transcript.extend_from_slice(&new_epoch.to_le_bytes());
        let dual_sig = ik.sign(&transcript)?;
        let dummy_secret = crate::primitives::concat_hash(&new_bundle.signed_prekey, b"reset-derivation");
        let ratchet = TripleRatchetAdapter::new(&dummy_secret, self.config.ratchet_config.clone());
        self.ratchet = Some(Mutex::new(ratchet));
        self.state = SessionState::Established;
        log::info!("Session reset initiated, epoch: {}", new_epoch);
        Ok(SessionReset { new_bundle, sender_ik_pub: ik_pub, dual_signature: dual_sig.ed25519_sig.to_vec(), epoch_counter: new_epoch })
    }

    pub async fn apply_reset(&mut self, reset: &SessionReset) -> Result<()> {
        { let epoch = self.epoch_counter.lock().await; epoch.validate_remote(reset.epoch_counter)?; }
        { let mut epoch = self.epoch_counter.lock().await; epoch.value = reset.epoch_counter; }
        self.process_prekey_bundle(&reset.new_bundle).await?;
        log::info!("Session reset applied, new epoch: {}", reset.epoch_counter);
        Ok(())
    }

    pub fn needs_reset(&self) -> bool { matches!(self.state, SessionState::NeedsReset) }
    pub fn state(&self) -> &SessionState { &self.state }
}
