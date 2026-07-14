use kassiber_crypto::*;
use kassiber_transport::{TransportCodec, TransportConfig};
use std::sync::Arc;

uniffi::setup_scaffolding!();

#[derive(uniffi::Error)]
pub enum KassiberFfiError {
    Crypto { msg: String },
    Transport { msg: String },
    SessionNotInitialized,
    EncryptionFailed,
    DecryptionFailed,
}

impl From<kassiber_crypto::KassiberError> for KassiberFfiError {
    fn from(e: kassiber_crypto::KassiberError) -> Self {
        KassiberFfiError::Crypto { msg: e.to_string() }
    }
}

#[uniffi::export(callback_interface)]
pub trait KassiberCallback: Send + Sync {
    fn on_decrypt_result(&self, plaintext: Vec<u8>, counter: u32);
    fn on_encrypt_result(&self, ciphertext: Vec<u8>, counter: u32);
    fn on_error(&self, error: String);
}

#[derive(uniffi::Object)]
pub struct KassiberHandle {
    inner: std::sync::Mutex<Option<InnerState>>,
}

struct InnerState {
    keystore: Arc<AsyncKeystoreActor>,
    codec: TransportCodec,
}

#[uniffi::export]
impl KassiberHandle {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self { inner: std::sync::Mutex::new(None) }
    }

    pub fn initialize(&self) -> Result<(), KassiberFfiError> {
        let rt = tokio::runtime::Runtime::new().map_err(|e| KassiberFfiError::Crypto { msg: e.to_string() })?;
        let keystore = Arc::new(rt.block_on(async { AsyncKeystoreActor::start(KeystoreConfig::default()) }));
        let codec = TransportCodec::new(TransportConfig::default());
        let mut guard = self.inner.lock().unwrap();
        *guard = Some(InnerState { keystore, codec });
        Ok(())
    }

    pub fn encrypt_for_carrier(&self, plaintext: Vec<u8>) -> Result<String, KassiberFfiError> {
        let guard = self.inner.lock().unwrap();
        let state = guard.as_ref().ok_or(KassiberFfiError::SessionNotInitialized)?;
        state.codec.encode_single(&plaintext).map_err(|e| KassiberFfiError::Transport { msg: e.to_string() })
    }

    pub fn decrypt_from_carrier(&self, carrier_text: String) -> Result<Option<Vec<u8>>, KassiberFfiError> {
        let guard = self.inner.lock().unwrap();
        let state = guard.as_ref().ok_or(KassiberFfiError::SessionNotInitialized)?;
        state.codec.decode_from_carrier(&carrier_text).map_err(|e| KassiberFfiError::Transport { msg: e.to_string() })
    }

    pub fn detect_kassiber(&self, text: String) -> bool {
        TransportCodec::detect_kassiber(&text)
    }

    pub fn status(&self) -> String {
        let guard = self.inner.lock().unwrap();
        match guard.as_ref() { Some(_) => "initialized".to_string(), None => "uninitialized".to_string() }
    }
}

#[uniffi::export]
pub fn kassiber_init() -> String { "KASSIBER FFI initialized".to_string() }

#[uniffi::export]
pub fn test_pqc_keygen() -> Result<Vec<u8>, KassiberFfiError> {
    use rand::thread_rng;
    let mut rng = thread_rng();
    let kp = HybridKeyPair::generate(&mut rng).map_err(|e| KassiberFfiError::Crypto { msg: e.to_string() })?;
    Ok(kp.public_key().pq_encap.bytes)
}

#[uniffi::export]
pub fn test_aes_roundtrip(plaintext: Vec<u8>) -> Result<bool, KassiberFfiError> {
    use kassiber_crypto::Aes256GcmKey;
    let key = Aes256GcmKey::from_shared_secret(b"test_key_32_bytes_for_testing!");
    let encrypted = key.encrypt(&plaintext, b"aad").map_err(|_| KassiberFfiError::EncryptionFailed)?;
    let decrypted = key.decrypt(&encrypted, b"aad").map_err(|_| KassiberFfiError::DecryptionFailed)?;
    Ok(decrypted == plaintext)
}
