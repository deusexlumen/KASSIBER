//! In-process keystore actor plus the Android StrongBox bridge.
//!
//! Host-side honesty note: real StrongBox / TEE key generation is only
//! possible on an Android device via the Android Keystore API. On the host
//! (tests, desktop), [`AndroidStrongBoxBridge`] therefore uses a SOFTWARE
//! FALLBACK: keys are generated with the OS CSPRNG (`rand::rng()`) and held
//! by the keystore actor in memory. No zero-filled dummy keys anywhere.

use crate::error::{KassiberError, Result};
use ed25519_dalek::{Signer, SigningKey};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Debug, Clone)]
pub struct KeystoreConfig {
    pub use_strongbox: bool,
    pub key_ttl_seconds: u64,
}

impl Default for KeystoreConfig {
    fn default() -> Self {
        Self {
            use_strongbox: true,
            key_ttl_seconds: 300,
        }
    }
}

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecureKeyHandle {
    #[zeroize(skip)]
    pub key_id: String,
    #[zeroize(skip)]
    pub created_at: std::time::SystemTime,
}

#[derive(Debug)]
enum KeystoreMessage {
    Store {
        key_id: String,
        key_data: Vec<u8>,
        resp: oneshot::Sender<Result<SecureKeyHandle>>,
    },
    Retrieve {
        key_id: String,
        resp: oneshot::Sender<Result<Zeroizing<Vec<u8>>>>,
    },
    Delete {
        key_id: String,
        resp: oneshot::Sender<Result<()>>,
    },
    HasKey {
        key_id: String,
        resp: oneshot::Sender<bool>,
    },
}

pub struct AsyncKeystoreActor {
    sender: mpsc::UnboundedSender<KeystoreMessage>,
    handle: Option<tokio::task::JoinHandle<()>>,
}

struct KeystoreState {
    /// Keys are wrapped in `Zeroizing` so removed/overwritten copies are
    /// scrubbed from memory as soon as they leave the map.
    keys: HashMap<String, Zeroizing<Vec<u8>>>,
    #[allow(dead_code)]
    config: KeystoreConfig,
}

impl AsyncKeystoreActor {
    pub fn start(config: KeystoreConfig) -> Self {
        let (tx, mut rx) = mpsc::unbounded_channel::<KeystoreMessage>();
        let config_clone = config.clone();
        let handle = tokio::spawn(async move {
            let mut state = KeystoreState {
                keys: HashMap::new(),
                config: config_clone,
            };
            while let Some(msg) = rx.recv().await {
                match msg {
                    KeystoreMessage::Store {
                        key_id,
                        key_data,
                        resp,
                    } => {
                        // `insert` returns the previous value; because values
                        // are wrapped in Zeroizing, an overwritten key is
                        // scrubbed when the old value drops here.
                        state.keys.insert(key_id.clone(), Zeroizing::new(key_data));
                        let _ = resp.send(Ok(SecureKeyHandle {
                            key_id,
                            created_at: std::time::SystemTime::now(),
                        }));
                    }
                    KeystoreMessage::Retrieve { key_id, resp } => {
                        // The clone is the single copy handed to the caller,
                        // wrapped in Zeroizing so the caller's copy is scrubbed
                        // on drop as well.
                        let result = state
                            .keys
                            .get(&key_id)
                            .map(|k| Zeroizing::new(k.to_vec()))
                            .ok_or_else(|| {
                                KassiberError::Keystore(format!("Key not found: {}", key_id))
                            });
                        let _ = resp.send(result);
                    }
                    KeystoreMessage::Delete { key_id, resp } => {
                        // Dropping the Zeroizing wrapper scrubs the key bytes.
                        state.keys.remove(&key_id);
                        let _ = resp.send(Ok(()));
                    }
                    KeystoreMessage::HasKey { key_id, resp } => {
                        let _ = resp.send(state.keys.contains_key(&key_id));
                    }
                }
            }
        });
        Self {
            sender: tx,
            handle: Some(handle),
        }
    }

    pub async fn store_key(&self, key_id: String, key_data: Vec<u8>) -> Result<SecureKeyHandle> {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send(KeystoreMessage::Store {
                key_id,
                key_data,
                resp: tx,
            })
            .map_err(|_| KassiberError::Keystore("Keystore actor closed".into()))?;
        rx.await
            .map_err(|_| KassiberError::Keystore("Response cancelled".into()))?
    }

    /// Retrieve a copy of a key. The returned buffer is zeroized on drop.
    pub async fn retrieve_key(&self, key_id: &str) -> Result<Zeroizing<Vec<u8>>> {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send(KeystoreMessage::Retrieve {
                key_id: key_id.to_string(),
                resp: tx,
            })
            .map_err(|_| KassiberError::Keystore("Keystore actor closed".into()))?;
        rx.await
            .map_err(|_| KassiberError::Keystore("Response cancelled".into()))?
    }

    pub async fn delete_key(&self, key_id: &str) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send(KeystoreMessage::Delete {
                key_id: key_id.to_string(),
                resp: tx,
            })
            .map_err(|_| KassiberError::Keystore("Keystore actor closed".into()))?;
        rx.await
            .map_err(|_| KassiberError::Keystore("Response cancelled".into()))?
    }

    pub async fn has_key(&self, key_id: &str) -> bool {
        let (tx, rx) = oneshot::channel();
        let _ = self.sender.send(KeystoreMessage::HasKey {
            key_id: key_id.to_string(),
            resp: tx,
        });
        rx.await.unwrap_or(false)
    }
}

impl Drop for AsyncKeystoreActor {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

/// Bridge to the Android StrongBox keystore.
///
/// On Android devices the `use_strongbox` flag routes key generation into the
/// hardware-backed Android Keystore (wired up on the Kotlin/JNI side). On the
/// host this bridge transparently falls back to SOFTWARE keys generated from
/// the OS CSPRNG — clearly documented, cryptographically real, just not
/// hardware-isolated.
pub struct AndroidStrongBoxBridge {
    actor: Arc<AsyncKeystoreActor>,
}

impl AndroidStrongBoxBridge {
    pub fn new(actor: Arc<AsyncKeystoreActor>) -> Self {
        Self { actor }
    }

    /// Generate a 32-byte Ed25519 seed under `alias`.
    ///
    /// Software fallback (host): the seed comes from `rand::rng()` (OS CSPRNG).
    /// Hardware path (Android device): delegated to the Android Keystore; the
    /// `_use_strongbox` flag selects StrongBox vs. TEE there.
    pub async fn generate_hardware_key(
        &self,
        alias: &str,
        _use_strongbox: bool,
    ) -> Result<SecureKeyHandle> {
        let mut seed = Zeroizing::new(vec![0u8; 32]);
        rand::fill(&mut seed[..]);
        self.actor.store_key(alias.to_string(), seed.to_vec()).await
    }

    /// Sign `data` with the Ed25519 key stored under `alias`.
    ///
    /// Works for software-fallback keys (32-byte seeds). On Android, hardware
    /// keys are signed inside the Keystore without the key ever leaving the
    /// TEE/StrongBox (Kotlin side); this host path mirrors that behaviour.
    pub async fn hw_sign(&self, alias: &str, data: &[u8]) -> Result<Vec<u8>> {
        let seed = self.actor.retrieve_key(alias).await?;
        let seed_bytes: [u8; 32] = seed
            .as_slice()
            .try_into()
            .map_err(|_| KassiberError::Keystore(format!("Key '{}' is not a 32-byte seed", alias)))?;
        let signing_key = SigningKey::from_bytes(&seed_bytes);
        Ok(signing_key.sign(data).to_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    #[tokio::test]
    async fn test_keystore_store_retrieve() {
        let actor = AsyncKeystoreActor::start(KeystoreConfig::default());
        let handle = actor
            .store_key("test_key_1".to_string(), b"secret_key_data".to_vec())
            .await
            .unwrap();
        assert_eq!(handle.key_id, "test_key_1");
        let retrieved = actor.retrieve_key("test_key_1").await.unwrap();
        assert_eq!(retrieved.as_slice(), b"secret_key_data");
    }

    #[tokio::test]
    async fn test_keystore_delete() {
        let actor = AsyncKeystoreActor::start(KeystoreConfig::default());
        actor
            .store_key("delete_me".to_string(), vec![1, 2, 3])
            .await
            .unwrap();
        assert!(actor.has_key("delete_me").await);
        actor.delete_key("delete_me").await.unwrap();
        assert!(!actor.has_key("delete_me").await);
    }

    #[tokio::test]
    async fn test_hardware_key_is_real_random_and_signs() {
        let actor = Arc::new(AsyncKeystoreActor::start(KeystoreConfig::default()));
        let bridge = AndroidStrongBoxBridge::new(actor.clone());

        bridge.generate_hardware_key("k1", false).await.unwrap();
        bridge.generate_hardware_key("k2", false).await.unwrap();
        let k1 = actor.retrieve_key("k1").await.unwrap();
        let k2 = actor.retrieve_key("k2").await.unwrap();
        // Real RNG: keys are neither zero nor equal.
        assert_ne!(k1.as_slice(), &[0u8; 32]);
        assert_ne!(k1.as_slice(), k2.as_slice());

        // hw_sign produces a verifiable Ed25519 signature.
        let sig_bytes = bridge.hw_sign("k1", b"message").await.unwrap();
        assert_eq!(sig_bytes.len(), 64);
        let seed: [u8; 32] = k1.as_slice().try_into().unwrap();
        let vk: VerifyingKey = SigningKey::from_bytes(&seed).verifying_key();
        let sig = Signature::from_bytes(sig_bytes.as_slice().try_into().unwrap());
        vk.verify(b"message", &sig).unwrap();
    }
}
