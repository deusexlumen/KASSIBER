use crate::error::{KassiberError, Result};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, Mutex};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone)]
pub struct KeystoreConfig {
    pub use_strongbox: bool,
    pub key_ttl_seconds: u64,
}

impl Default for KeystoreConfig {
    fn default() -> Self {
        Self { use_strongbox: true, key_ttl_seconds: 300 }
    }
}

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecureKeyHandle {
    pub key_id: String,
    #[zeroize(skip)]
    pub created_at: std::time::SystemTime,
}

#[derive(Debug)]
enum KeystoreMessage {
    Store { key_id: String, key_data: Vec<u8>, resp: oneshot::Sender<Result<SecureKeyHandle>> },
    Retrieve { key_id: String, resp: oneshot::Sender<Result<Vec<u8>>> },
    Delete { key_id: String, resp: oneshot::Sender<Result<()>> },
    HasKey { key_id: String, resp: oneshot::Sender<bool> },
}

pub struct AsyncKeystoreActor {
    sender: mpsc::UnboundedSender<KeystoreMessage>,
    handle: Option<tokio::task::JoinHandle<()>>,
}

struct KeystoreState {
    keys: HashMap<String, Vec<u8>>,
    config: KeystoreConfig,
}

impl AsyncKeystoreActor {
    pub fn start(config: KeystoreConfig) -> Self {
        let (tx, mut rx) = mpsc::unbounded_channel::<KeystoreMessage>();
        let config_clone = config.clone();
        let handle = tokio::spawn(async move {
            let mut state = KeystoreState { keys: HashMap::new(), config: config_clone };
            while let Some(msg) = rx.recv().await {
                match msg {
                    KeystoreMessage::Store { key_id, key_data, resp } => {
                        state.keys.insert(key_id.clone(), key_data);
                        let _ = resp.send(Ok(SecureKeyHandle { key_id, created_at: std::time::SystemTime::now() }));
                    }
                    KeystoreMessage::Retrieve { key_id, resp } => {
                        let result = state.keys.get(&key_id).cloned()
                            .ok_or_else(|| KassiberError::Keystore(format!("Key not found: {}", key_id)));
                        let _ = resp.send(result);
                    }
                    KeystoreMessage::Delete { key_id, resp } => {
                        if let Some(mut data) = state.keys.remove(&key_id) { data.zeroize(); }
                        let _ = resp.send(Ok(()));
                    }
                    KeystoreMessage::HasKey { key_id, resp } => {
                        let _ = resp.send(state.keys.contains_key(&key_id));
                    }
                }
            }
        });
        Self { sender: tx, handle: Some(handle) }
    }

    pub async fn store_key(&self, key_id: String, key_data: Vec<u8>) -> Result<SecureKeyHandle> {
        let (tx, rx) = oneshot::channel();
        self.sender.send(KeystoreMessage::Store { key_id, key_data, resp: tx })
            .map_err(|_| KassiberError::Keystore("Keystore actor closed".into()))?;
        rx.await.map_err(|_| KassiberError::Keystore("Response cancelled".into()))?
    }

    pub async fn retrieve_key(&self, key_id: &str) -> Result<Vec<u8>> {
        let (tx, rx) = oneshot::channel();
        self.sender.send(KeystoreMessage::Retrieve { key_id: key_id.to_string(), resp: tx })
            .map_err(|_| KassiberError::Keystore("Keystore actor closed".into()))?;
        rx.await.map_err(|_| KassiberError::Keystore("Response cancelled".into()))?
    }

    pub async fn delete_key(&self, key_id: &str) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.sender.send(KeystoreMessage::Delete { key_id: key_id.to_string(), resp: tx })
            .map_err(|_| KassiberError::Keystore("Keystore actor closed".into()))?;
        rx.await.map_err(|_| KassiberError::Keystore("Response cancelled".into()))?
    }

    pub async fn has_key(&self, key_id: &str) -> bool {
        let (tx, rx) = oneshot::channel();
        let _ = self.sender.send(KeystoreMessage::HasKey { key_id: key_id.to_string(), resp: tx });
        rx.await.unwrap_or(false)
    }
}

impl Drop for AsyncKeystoreActor {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() { handle.abort(); }
    }
}

pub struct AndroidStrongBoxBridge {
    actor: Arc<AsyncKeystoreActor>,
}

impl AndroidStrongBoxBridge {
    pub fn new(actor: Arc<AsyncKeystoreActor>) -> Self { Self { actor } }

    pub async fn generate_hardware_key(&self, alias: &str, _use_strongbox: bool) -> Result<SecureKeyHandle> {
        let dummy_key = vec![0u8; 32];
        self.actor.store_key(alias.to_string(), dummy_key).await
    }

    pub async fn hw_sign(&self, _alias: &str, _data: &[u8]) -> Result<Vec<u8>> {
        Err(KassiberError::Keystore("HW signing not yet implemented".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_keystore_store_retrieve() {
        let actor = AsyncKeystoreActor::start(KeystoreConfig::default());
        let handle = actor.store_key("test_key_1".to_string(), b"secret_key_data".to_vec()).await.unwrap();
        assert_eq!(handle.key_id, "test_key_1");
        let retrieved = actor.retrieve_key("test_key_1").await.unwrap();
        assert_eq!(retrieved, b"secret_key_data");
    }

    #[tokio::test]
    async fn test_keystore_delete() {
        let actor = AsyncKeystoreActor::start(KeystoreConfig::default());
        actor.store_key("delete_me".to_string(), vec![1, 2, 3]).await.unwrap();
        assert!(actor.has_key("delete_me").await);
        actor.delete_key("delete_me").await.unwrap();
        assert!(!actor.has_key("delete_me").await);
    }
}
