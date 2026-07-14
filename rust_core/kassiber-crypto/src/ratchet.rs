use crate::error::{KassiberError, Result};
use crate::primitives::{concat_hash, Aes256GcmKey, AesAead};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone)]
pub struct RatchetConfig {
    pub max_messages_per_phase: u32,
    pub max_lookahead: u32,
    pub rekey_interval_secs: u64,
}

impl Default for RatchetConfig {
    fn default() -> Self {
        Self { max_messages_per_phase: 1000, max_lookahead: 2000, rekey_interval_secs: 86400 }
    }
}

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct SpqrRatchet {
    #[zeroize(skip)]
    pub send_chain_key: Option<[u8; 32]>,
    #[zeroize(skip)]
    pub recv_chain_key: Option<[u8; 32]>,
    root_key: [u8; 32],
    pub send_counter: u32,
    pub recv_counter: u32,
    last_ratchet_pubkey: Option<[u8; 32]>,
    config: RatchetConfig,
}

pub struct TripleRatchetAdapter {
    pub spqr: SpqrRatchet,
    pub signal_store: Option<()>,
}

#[derive(Debug)]
pub struct RatchetStep {
    pub message_key: [u8; 32],
    pub next_chain_key: [u8; 32],
}

impl SpqrRatchet {
    pub fn initialize(shared_secret: &[u8], config: RatchetConfig) -> Self {
        let root_key = concat_hash(shared_secret, b"kassiber-spqr-root");
        let mut send_ck = [0u8; 32];
        send_ck.copy_from_slice(&concat_hash(&root_key, b"chain-send-init"));
        let mut recv_ck = [0u8; 32];
        recv_ck.copy_from_slice(&concat_hash(&root_key, b"chain-recv-init"));
        Self { send_chain_key: Some(send_ck), recv_chain_key: Some(recv_ck), root_key, send_counter: 0, recv_counter: 0, last_ratchet_pubkey: None, config }
    }

    pub fn next_send_key(&mut self) -> Result<RatchetStep> {
        let ck = self.send_chain_key.ok_or_else(|| KassiberError::RatchetDesync("No send chain key".into()))?;
        if self.send_counter >= self.config.max_messages_per_phase {
            return Err(KassiberError::RatchetDesync("Max messages per phase exceeded".into()));
        }
        let mk = concat_hash(&ck, &self.send_counter.to_le_bytes());
        let next_ck = concat_hash(&ck, b"ratchet-step");
        self.send_chain_key = Some(next_ck);
        self.send_counter += 1;
        Ok(RatchetStep { message_key: mk, next_chain_key: next_ck })
    }

    pub fn recv_key_at(&mut self, counter: u32) -> Result<RatchetStep> {
        let ck = self.recv_chain_key.ok_or_else(|| KassiberError::RatchetDesync("No recv chain key".into()))?;
        if counter > self.recv_counter + self.config.max_lookahead {
            return Err(KassiberError::RatchetDesync(format!("Counter {} too far ahead of {}", counter, self.recv_counter)));
        }
        let mut current_ck = ck;
        let mut current_counter = self.recv_counter;
        while current_counter < counter {
            current_ck = concat_hash(&current_ck, b"ratchet-step");
            current_counter += 1;
        }
        let mk = concat_hash(&current_ck, &counter.to_le_bytes());
        let next_ck = concat_hash(&current_ck, b"ratchet-step");
        self.recv_chain_key = Some(next_ck);
        self.recv_counter = counter + 1;
        Ok(RatchetStep { message_key: mk, next_chain_key: next_ck })
    }

    pub fn dh_ratchet_step(&mut self, their_pubkey: [u8; 32], our_dh_secret: &[u8; 32]) -> Result<()> {
        let dh_input = concat_hash(our_dh_secret, &their_pubkey);
        self.root_key = concat_hash(&self.root_key, &dh_input);
        let mut new_send_ck = [0u8; 32];
        new_send_ck.copy_from_slice(&concat_hash(&self.root_key, b"ratchet-send"));
        let mut new_recv_ck = [0u8; 32];
        new_recv_ck.copy_from_slice(&concat_hash(&self.root_key, b"ratchet-recv"));
        self.send_chain_key = Some(new_send_ck);
        self.recv_chain_key = Some(new_recv_ck);
        self.send_counter = 0;
        self.recv_counter = 0;
        self.last_ratchet_pubkey = Some(their_pubkey);
        Ok(())
    }

    pub fn needs_rekey(&self) -> bool {
        self.send_counter >= self.config.max_messages_per_phase
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut state = Vec::new();
        state.extend_from_slice(&self.root_key);
        state.extend_from_slice(&self.send_counter.to_le_bytes());
        state.extend_from_slice(&self.recv_counter.to_le_bytes());
        if let Some(pubkey) = self.last_ratchet_pubkey { state.extend_from_slice(&pubkey); }
        state
    }
}

impl TripleRatchetAdapter {
    pub fn new(shared_secret: &[u8], config: RatchetConfig) -> Self {
        Self { spqr: SpqrRatchet::initialize(shared_secret, config), signal_store: None }
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

    #[test]
    fn test_spqr_roundtrip() {
        let secret = b"test_shared_secret_32_bytes_long";
        let mut alice = SpqrRatchet::initialize(secret, RatchetConfig::default());
        let mut bob = SpqrRatchet::initialize(secret, RatchetConfig::default());
        let step = alice.next_send_key().unwrap();
        let key1 = Aes256GcmKey::from_shared_secret(&step.message_key);
        let ct = key1.encrypt(b"hello", b"aad").unwrap();
        let recv_step = bob.recv_key_at(0).unwrap();
        let key2 = Aes256GcmKey::from_shared_secret(&recv_step.message_key);
        let pt = key2.decrypt(&ct, b"aad").unwrap();
        assert_eq!(pt, b"hello");
    }

    #[test]
    fn test_triple_ratchet_adapter() {
        let secret = b"adapter_secret_32_bytes_longgg";
        let mut alice = TripleRatchetAdapter::new(secret, RatchetConfig::default());
        let mut bob = TripleRatchetAdapter::new(secret, RatchetConfig::default());
        let (ct, counter) = alice.encrypt(b"test message", b"aad").unwrap();
        let pt = bob.decrypt(counter, &ct, b"aad").unwrap();
        assert_eq!(pt, b"test message");
    }
}
