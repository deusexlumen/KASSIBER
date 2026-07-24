//! KASSIBER UniFFI layer: identity, handshake and carrier messaging.
//!
//! The Android app talks to exactly one exported object, [`KassiberIdentity`]:
//!
//! 1. `KassiberIdentity::create()` generates a fresh identity (ML-DSA-65 +
//!    Ed25519 + X25519 keypairs) inside a real [`KassiberSession`].
//! 2. Onboarding (BLE/QR) exchanges `export_prekey_bundle()` bytes. The
//!    initiator calls `initiate_session(bundle)` and sends the resulting
//!    handshake bytes; the responder completes with `accept_session(handshake)`.
//! 3. Messaging goes through `encrypt_for_carrier` / `decrypt_from_carrier`,
//!    which do REAL session encryption (ratcheted AES-256-GCM) wrapped in the
//!    dictionary transport codec with the `<<<KASSIBER>>>` marker.
//!
//! Runtime note: `KassiberSession` is async (tokio). The FFI layer is
//! synchronous, so a single process-global multi-threaded tokio runtime is
//! held in a `OnceLock` for the entire process lifetime. That also keeps the
//! keystore actor (spawned on this runtime) alive — the previous design
//! dropped a local runtime right after `initialize`, killing the actor.

use kassiber_crypto::{
    AsyncKeystoreActor, AesAead, HandshakeMessage, HybridKeyPair, KassiberSession, KeystoreConfig,
    PrekeyBundle, SessionConfig, SessionState,
};
use kassiber_transport::{TransportCodec, TransportConfig};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use tokio::runtime::Runtime;

uniffi::setup_scaffolding!();

/// AAD bound into every carrier message. Domain-separates session ciphertexts
/// from any other AES-GCM usage and authenticates the transport context.
const CARRIER_AAD: &[u8] = b"kassiber-carrier-v1";

/// Wire layout of one encrypted session message inside the carrier encoding:
/// `counter (u32 LE) || nonce (12B) || tag (16B) || ciphertext`.
const COUNTER_LEN: usize = 4;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const HEADER_LEN: usize = COUNTER_LEN + NONCE_LEN + TAG_LEN;

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum KassiberFfiError {
    #[error("crypto error: {msg}")]
    Crypto { msg: String },
    #[error("transport error: {msg}")]
    Transport { msg: String },
    #[error("serialization error: {msg}")]
    Serialization { msg: String },
    #[error("session not established")]
    SessionNotEstablished,
    #[error("internal error: {msg}")]
    Internal { msg: String },
}

impl From<kassiber_crypto::KassiberError> for KassiberFfiError {
    fn from(e: kassiber_crypto::KassiberError) -> Self {
        KassiberFfiError::Crypto { msg: e.to_string() }
    }
}

impl From<kassiber_transport::TransportError> for KassiberFfiError {
    fn from(e: kassiber_transport::TransportError) -> Self {
        KassiberFfiError::Transport { msg: e.to_string() }
    }
}

impl From<postcard::Error> for KassiberFfiError {
    fn from(e: postcard::Error) -> Self {
        KassiberFfiError::Serialization { msg: e.to_string() }
    }
}

/// Process-global tokio runtime. Created lazily on first use and never
/// dropped, so every actor spawned on it (keystore) lives as long as the
/// process — no per-call runtimes that die on scope exit.
static RUNTIME: OnceLock<std::result::Result<Runtime, String>> = OnceLock::new();

fn runtime() -> Result<&'static Runtime, KassiberFfiError> {
    RUNTIME
        .get_or_init(|| Runtime::new().map_err(|e| format!("tokio runtime init: {e}")))
        .as_ref()
        .map_err(|msg| KassiberFfiError::Internal { msg: msg.clone() })
}

fn pack_message(counter: u32, aead: &AesAead) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + aead.ciphertext.len());
    out.extend_from_slice(&counter.to_le_bytes());
    out.extend_from_slice(&aead.nonce);
    out.extend_from_slice(&aead.tag);
    out.extend_from_slice(&aead.ciphertext);
    out
}

fn unpack_message(bytes: &[u8]) -> Result<(u32, AesAead), KassiberFfiError> {
    if bytes.len() < HEADER_LEN {
        return Err(KassiberFfiError::Serialization {
            msg: format!("message too short: {} bytes", bytes.len()),
        });
    }
    // Length was validated above, so indexing cannot fail.
    let counter = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&bytes[COUNTER_LEN..COUNTER_LEN + NONCE_LEN]);
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&bytes[COUNTER_LEN + NONCE_LEN..HEADER_LEN]);
    Ok((
        counter,
        AesAead {
            ciphertext: bytes[HEADER_LEN..].to_vec(),
            nonce,
            tag,
        },
    ))
}

/// One local identity with (at most) one established peer session.
///
/// All methods are synchronous over FFI; internally they block on the global
/// runtime. Lock poisoning is reported as an error instead of panicking.
#[derive(uniffi::Object)]
pub struct KassiberIdentity {
    session: Mutex<KassiberSession>,
}

impl KassiberIdentity {
    fn lock_session(&self) -> Result<MutexGuard<'_, KassiberSession>, KassiberFfiError> {
        self.session.lock().map_err(|_| KassiberFfiError::Internal {
            msg: "session lock poisoned".into(),
        })
    }
}

#[uniffi::export]
impl KassiberIdentity {
    /// Generate a fresh identity. The keystore actor is spawned on the global
    /// runtime, so it stays alive for the whole process.
    #[uniffi::constructor]
    pub fn create() -> Result<Arc<Self>, KassiberFfiError> {
        let rt = runtime()?;
        let keystore = rt.block_on(async { Arc::new(AsyncKeystoreActor::start(KeystoreConfig::default())) });
        let mut session = KassiberSession::new(keystore, SessionConfig::default());
        rt.block_on(session.initialize())?;
        Ok(Arc::new(Self {
            session: Mutex::new(session),
        }))
    }

    /// postcard-serialized [`PrekeyBundle`] for onboarding (BLE/QR). Also
    /// stores the matching secret prekey locally for `accept_session`.
    pub fn export_prekey_bundle(&self) -> Result<Vec<u8>, KassiberFfiError> {
        let mut session = self.lock_session()?;
        let bundle = runtime()?.block_on(session.generate_prekey_bundle())?;
        Ok(postcard::to_allocvec(&bundle)?)
    }

    /// Initiator side: verify the peer's bundle and produce the handshake
    /// message (postcard-serialized [`HandshakeMessage`]) to send back.
    /// The session is established once this returns.
    pub fn initiate_session(&self, bundle_bytes: Vec<u8>) -> Result<Vec<u8>, KassiberFfiError> {
        let bundle: PrekeyBundle = postcard::from_bytes(&bundle_bytes)?;
        let mut session = self.lock_session()?;
        let handshake = runtime()?.block_on(session.process_prekey_bundle(&bundle))?;
        Ok(postcard::to_allocvec(&handshake)?)
    }

    /// Responder side: complete the handshake with the message produced by
    /// the peer's `initiate_session`.
    pub fn accept_session(&self, handshake_bytes: Vec<u8>) -> Result<(), KassiberFfiError> {
        let handshake: HandshakeMessage = postcard::from_bytes(&handshake_bytes)?;
        let mut session = self.lock_session()?;
        Ok(runtime()?.block_on(session.accept_handshake(&handshake))?)
    }

    pub fn is_session_established(&self) -> bool {
        match self.session.lock() {
            Ok(session) => matches!(session.state(), SessionState::Established),
            Err(_) => false,
        }
    }

    /// Encrypt with the ratcheted session key and encode as a marked carrier
    /// string (`<<<KASSIBER>>>` … `<<<KASSIBER>>>`). Fails with
    /// [`KassiberFfiError::SessionNotEstablished`] before onboarding finished.
    pub fn encrypt_for_carrier(&self, plaintext: Vec<u8>) -> Result<String, KassiberFfiError> {
        let session = self.lock_session()?;
        if !matches!(session.state(), SessionState::Established) {
            return Err(KassiberFfiError::SessionNotEstablished);
        }
        let (aead, counter) = runtime()?.block_on(session.encrypt(&plaintext, CARRIER_AAD))?;
        let codec = TransportCodec::new(TransportConfig::default());
        Ok(codec.encode_single(&pack_message(counter, &aead))?)
    }

    /// Marker check, carrier decode and session decrypt. Returns `None` when
    /// the text carries no KASSIBER payload; decode/decrypt failures are
    /// errors (a marked payload must be genuine).
    pub fn decrypt_from_carrier(
        &self,
        carrier_text: String,
    ) -> Result<Option<Vec<u8>>, KassiberFfiError> {
        if !TransportCodec::detect_kassiber(&carrier_text) {
            return Ok(None);
        }
        let session = self.lock_session()?;
        if !matches!(session.state(), SessionState::Established) {
            return Err(KassiberFfiError::SessionNotEstablished);
        }
        let codec = TransportCodec::new(TransportConfig::default());
        let payload = match codec.decode_from_carrier(&carrier_text)? {
            Some(payload) => payload,
            None => return Ok(None),
        };
        let (counter, aead) = unpack_message(&payload)?;
        let result = runtime()?.block_on(session.decrypt(counter, &aead, CARRIER_AAD))?;
        Ok(Some(result.plaintext))
    }
}

/// Pure marker check; never touches session state and never fails.
#[uniffi::export]
pub fn detect_kassiber(text: String) -> bool {
    TransportCodec::detect_kassiber(&text)
}

/// Smoke test helper: returns a real ML-KEM-768 encapsulation public key.
#[uniffi::export]
pub fn test_pqc_keygen() -> Result<Vec<u8>, KassiberFfiError> {
    let mut rng = rand::rng();
    let kp = HybridKeyPair::generate(&mut rng)?;
    Ok(kp.public_key().pq_encap.bytes)
}

/// Smoke test helper: real AES-256-GCM roundtrip with a random nonce.
#[uniffi::export]
pub fn test_aes_roundtrip(plaintext: Vec<u8>) -> Result<bool, KassiberFfiError> {
    use kassiber_crypto::Aes256GcmKey;
    let key = Aes256GcmKey::from_shared_secret(b"test_key_32_bytes_for_testing!");
    let encrypted = key.encrypt(&plaintext, b"aad")?;
    let decrypted = key.decrypt(&encrypted, b"aad")?;
    Ok(decrypted == plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Full FFI flow: two identities, bundle exchange, handshake on both
    /// sides, encrypted carrier message in both directions.
    #[test]
    fn test_full_flow_over_ffi() {
        let alice = KassiberIdentity::create().unwrap();
        let bob = KassiberIdentity::create().unwrap();
        assert!(!alice.is_session_established());
        assert!(!bob.is_session_established());

        // Onboarding: Bob publishes a bundle, Alice initiates, Bob accepts.
        let bundle = bob.export_prekey_bundle().unwrap();
        let handshake = alice.initiate_session(bundle).unwrap();
        bob.accept_session(handshake).unwrap();
        assert!(alice.is_session_established());
        assert!(bob.is_session_established());

        // Alice -> Bob through the carrier encoding.
        let carrier = alice.encrypt_for_carrier(b"hello bob".to_vec()).unwrap();
        assert!(detect_kassiber(carrier.clone()));
        let plaintext = bob.decrypt_from_carrier(carrier).unwrap().unwrap();
        assert_eq!(plaintext, b"hello bob");

        // Bob -> Alice (mirrored ratchet chains).
        let reply = bob.encrypt_for_carrier(b"hello alice".to_vec()).unwrap();
        let plaintext = alice.decrypt_from_carrier(reply).unwrap().unwrap();
        assert_eq!(plaintext, b"hello alice");

        // Text without the marker is not a payload.
        assert_eq!(
            alice.decrypt_from_carrier("just a normal chat message".to_string()).unwrap(),
            None
        );
    }

    #[test]
    fn test_tampered_bundle_and_carrier_rejected() {
        let alice = KassiberIdentity::create().unwrap();
        let bob = KassiberIdentity::create().unwrap();

        // A bit-flipped bundle must fail signature verification.
        let mut bundle = bob.export_prekey_bundle().unwrap();
        let mid = bundle.len() / 2;
        bundle[mid] ^= 0x01;
        assert!(alice.initiate_session(bundle.clone()).is_err());
        assert!(!alice.is_session_established());

        // Garbage bytes are not a bundle at all.
        assert!(alice.initiate_session(vec![0xAA; 32]).is_err());

        // The genuine bundle still works (no state was poisoned).
        let good = bob.export_prekey_bundle().unwrap();
        let handshake = alice.initiate_session(good).unwrap();
        bob.accept_session(handshake).unwrap();

        // A tampered carrier string must fail (codec or AEAD tag), never
        // silently yield plaintext.
        let carrier = alice.encrypt_for_carrier(b"secret".to_vec()).unwrap();
        let mut tampered = carrier.clone();
        let pos = tampered.len() / 2;
        let replacement = if &tampered[pos..pos + 1] == "a" { "b" } else { "a" };
        tampered.replace_range(pos..pos + 1, replacement);
        assert_ne!(tampered, carrier);
        assert!(bob.decrypt_from_carrier(tampered).is_err());
    }

    #[test]
    fn test_messaging_requires_established_session() {
        let identity = KassiberIdentity::create().unwrap();
        assert!(matches!(
            identity.encrypt_for_carrier(b"nope".to_vec()),
            Err(KassiberFfiError::SessionNotEstablished)
        ));
        let marked = "<<<KASSIBER>>>\nsome words here\n<<<KASSIBER>>>".to_string();
        assert!(matches!(
            identity.decrypt_from_carrier(marked),
            Err(KassiberFfiError::SessionNotEstablished)
        ));
        // Unmarked text short-circuits to None even without a session.
        assert_eq!(identity.decrypt_from_carrier("hi".to_string()).unwrap(), None);
    }

    #[test]
    fn test_smoke_helpers() {
        assert_eq!(test_pqc_keygen().unwrap().len(), 1184); // ML-KEM-768 ek
        assert!(test_aes_roundtrip(b"roundtrip".to_vec()).unwrap());
    }
}
