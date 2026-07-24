//! Hybrid cryptographic primitives for KASSIBER.
//!
//! - KEM: ML-KEM-768 (FIPS 203) hybridized with X25519
//! - Signatures: ML-DSA-65 (FIPS 204) dual-signed with Ed25519
//! - AEAD: AES-256-GCM with explicit AAD
//! - KDF: HKDF-SHA-256 with explicit salt/info domain separation

use crate::error::{KassiberError, Result};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use ed25519_dalek::{Signature as EdSignature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use ml_dsa::{
    EncodedSignature as MlDsaEncodedSignature, EncodedVerifyingKey as MlDsaEncodedVk, Generate,
    Keypair, MlDsa65, Signature as MlDsaSignature, SigningKey as MlDsaSigningKey,
    VerifyingKey as MlDsaVerifyingKey,
};
use ml_kem::{Decapsulate, Encapsulate, Kem, MlKem768};
use rand_core::CryptoRng;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

const AES_KEY_SIZE: usize = 32;
const AES_NONCE_SIZE: usize = 12;

/// ML-KEM-768 encapsulation key (public), FIPS 203.
type KemEncapsulationKey = ml_kem::EncapsulationKey<MlKem768>;
/// ML-KEM-768 decapsulation key (secret), FIPS 203.
type KemDecapsulationKey = ml_kem::DecapsulationKey<MlKem768>;

/// Derive 32 bytes via HKDF-SHA-256 with explicit salt and info.
///
/// This replaces the former raw-SHA3 "KDF". `salt` may be empty (HKDF then
/// uses a zero salt per RFC 5869); `info` MUST be a domain-separation tag.
pub(crate) fn hkdf32(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
    let salt = if salt.is_empty() { None } else { Some(salt) };
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .expect("32 bytes is a valid HKDF-SHA-256 output length");
    okm
}

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct HybridKeyPair {
    pub pq: PostQuantumKeyPair,
    pub classical: X25519KeyPair,
}

#[derive(Debug, Clone)]
pub struct HybridPublicKey {
    pub pq_encap: PostQuantumPublicKey,
    pub classical_pub: [u8; 32],
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct HybridSecretKey {
    pq_decap: Vec<u8>,
    /// StaticSecret zeroizes itself on drop (x25519-dalek), hence the skip.
    #[zeroize(skip)]
    classical_secret: X25519StaticSecret,
}

impl std::fmt::Debug for HybridSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HybridSecretKey").finish_non_exhaustive()
    }
}

impl HybridSecretKey {
    /// Build a secret key view from an existing key pair.
    pub fn from_keypair(kp: &HybridKeyPair) -> Self {
        Self {
            pq_decap: kp.pq.secret.clone(),
            classical_secret: kp.classical.secret.clone(),
        }
    }
}

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct PostQuantumKeyPair {
    #[zeroize(skip)]
    pub public: Vec<u8>,
    pub secret: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct PostQuantumPublicKey {
    pub bytes: Vec<u8>,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct X25519KeyPair {
    #[zeroize(skip)]
    pub public: [u8; 32],
    /// StaticSecret zeroizes itself on drop (x25519-dalek), hence the skip.
    #[zeroize(skip)]
    pub secret: X25519StaticSecret,
}

impl std::fmt::Debug for X25519KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X25519KeyPair")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlDsa65KeyPair {
    #[zeroize(skip)]
    pub public: Vec<u8>,
    pub secret: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct DualKeyPair {
    pub ml_dsa: MlDsa65KeyPair,
    pub ed25519: SigningKey,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DualSignature {
    pub ml_dsa_sig: Vec<u8>,
    pub ed25519_sig: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct HybridCiphertext {
    pub pq_ct: Vec<u8>,
    pub ephemeral_pub: [u8; 32],
}

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct Aes256GcmKey {
    pub key: [u8; AES_KEY_SIZE],
}

#[derive(Debug, Clone)]
pub struct AesAead {
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; AES_NONCE_SIZE],
    pub tag: [u8; 16],
}

impl HybridKeyPair {
    pub fn generate<R: CryptoRng>(rng: &mut R) -> Result<Self> {
        let pq = PostQuantumKeyPair::generate_ml_kem768(rng)?;
        let classical = X25519KeyPair::generate(rng);
        Ok(Self { pq, classical })
    }

    pub fn public_key(&self) -> HybridPublicKey {
        HybridPublicKey {
            pq_encap: PostQuantumPublicKey {
                bytes: self.pq.public.clone(),
            },
            classical_pub: self.classical.public,
        }
    }

    /// Secret-key view used for hybrid decapsulation.
    pub fn secret_key(&self) -> HybridSecretKey {
        HybridSecretKey::from_keypair(self)
    }
}

impl PostQuantumKeyPair {
    /// Generate a real ML-KEM-768 (FIPS 203) key pair.
    ///
    /// `secret` holds the 64-byte decapsulation seed (d, z); `public` the
    /// 1184-byte encapsulation key.
    pub fn generate_ml_kem768<R: CryptoRng>(rng: &mut R) -> Result<Self> {
        let (dk, ek) = MlKem768::generate_keypair_from_rng(rng);
        Ok(Self {
            public: ml_kem::KeyExport::to_bytes(&ek).as_slice().to_vec(),
            secret: ml_kem::KeyExport::to_bytes(&dk).as_slice().to_vec(),
        })
    }

    fn decapsulation_key(&self) -> Result<KemDecapsulationKey> {
        <KemDecapsulationKey as ml_kem::KeyInit>::new_from_slice(&self.secret)
            .map_err(|_| KassiberError::Decryption("invalid ML-KEM-768 decapsulation key".into()))
    }

    /// Decapsulate an ML-KEM-768 ciphertext, returning the shared secret.
    pub fn decapsulate(&self, ct_bytes: &[u8]) -> Result<Vec<u8>> {
        let dk = self.decapsulation_key()?;
        let shared = dk
            .decapsulate_slice(ct_bytes)
            .map_err(|_| KassiberError::Decryption("invalid ML-KEM-768 ciphertext".into()))?;
        Ok(shared.as_slice().to_vec())
    }
}

impl PostQuantumPublicKey {
    /// Encapsulate against this ML-KEM-768 key; returns (shared_secret, ciphertext).
    pub fn encapsulate<R: CryptoRng>(&self, rng: &mut R) -> Result<(Vec<u8>, Vec<u8>)> {
        let ek = <KemEncapsulationKey as ml_kem::TryKeyInit>::new_from_slice(&self.bytes)
            .map_err(|_| KassiberError::Encryption("invalid ML-KEM-768 encapsulation key".into()))?;
        let (ct, shared) = ek.encapsulate_with_rng(rng);
        Ok((shared.as_slice().to_vec(), ct.as_slice().to_vec()))
    }
}

impl X25519KeyPair {
    pub fn generate<R: CryptoRng>(rng: &mut R) -> Self {
        let secret = X25519StaticSecret::random_from_rng(rng);
        let public = X25519PublicKey::from(&secret);
        Self {
            public: public.to_bytes(),
            secret,
        }
    }
}

impl MlDsa65KeyPair {
    /// Generate a real ML-DSA-65 (FIPS 204) key pair.
    ///
    /// `secret` holds the 32-byte signing seed; `public` the 1952-byte
    /// encoded verifying key.
    pub fn generate<R: CryptoRng>(rng: &mut R) -> Result<Self> {
        let sk = MlDsaSigningKey::<MlDsa65>::generate_from_rng(rng);
        Ok(Self {
            public: sk.verifying_key().encode().as_slice().to_vec(),
            secret: ml_dsa::KeyExport::to_bytes(&sk).as_slice().to_vec(),
        })
    }

    fn signing_key(&self) -> Result<MlDsaSigningKey<MlDsa65>> {
        let seed = ml_dsa::Seed::try_from(self.secret.as_slice())
            .map_err(|_| KassiberError::Signature("invalid ML-DSA-65 signing key".into()))?;
        Ok(<MlDsaSigningKey<MlDsa65> as ml_dsa::KeyInit>::new(&seed))
    }

    fn verifying_key_from_bytes(bytes: &[u8]) -> Result<MlDsaVerifyingKey<MlDsa65>> {
        let encoded = MlDsaEncodedVk::<MlDsa65>::try_from(bytes)
            .map_err(|_| KassiberError::SignatureVerification)?;
        Ok(MlDsaVerifyingKey::decode(&encoded))
    }
}

impl DualKeyPair {
    pub fn generate<R: CryptoRng>(rng: &mut R) -> Result<Self> {
        let ml_dsa = MlDsa65KeyPair::generate(rng)?;
        let ed25519 = SigningKey::generate(rng);
        Ok(Self { ml_dsa, ed25519 })
    }

    /// Public identity: (ML-DSA-65 verifying key, Ed25519 verifying key).
    pub fn verifying_keys(&self) -> (Vec<u8>, [u8; 32]) {
        (
            self.ml_dsa.public.clone(),
            self.ed25519.verifying_key().to_bytes(),
        )
    }

    /// Dual-sign `message` with both ML-DSA-65 and Ed25519.
    pub fn sign(&self, message: &[u8]) -> Result<DualSignature> {
        let ml_dsa_sk = self.ml_dsa.signing_key()?;
        let ml_dsa_sig = ml_dsa_sk.sign(message);
        let ed_sig: EdSignature = self.ed25519.sign(message);
        Ok(DualSignature {
            ml_dsa_sig: ml_dsa_sig.encode().as_slice().to_vec(),
            ed25519_sig: ed_sig.to_bytes().to_vec(),
        })
    }
}

impl DualSignature {
    /// Verify both halves of the dual signature. Fails unless BOTH are valid.
    pub fn verify(
        &self,
        message: &[u8],
        ml_dsa_public: &[u8],
        ed25519_public: &[u8],
    ) -> Result<()> {
        // ML-DSA-65 half
        let vk = MlDsa65KeyPair::verifying_key_from_bytes(ml_dsa_public)?;
        let sig_encoded = MlDsaEncodedSignature::<MlDsa65>::try_from(self.ml_dsa_sig.as_slice())
            .map_err(|_| KassiberError::SignatureVerification)?;
        let sig = MlDsaSignature::decode(&sig_encoded).ok_or(KassiberError::SignatureVerification)?;
        vk.verify(message, &sig)
            .map_err(|_| KassiberError::SignatureVerification)?;

        // Ed25519 half
        let ed_vk_bytes: [u8; 32] = ed25519_public
            .try_into()
            .map_err(|_| KassiberError::SignatureVerification)?;
        let ed_vk =
            VerifyingKey::from_bytes(&ed_vk_bytes).map_err(|_| KassiberError::SignatureVerification)?;
        let ed_sig_bytes: [u8; 64] = self
            .ed25519_sig
            .as_slice()
            .try_into()
            .map_err(|_| KassiberError::SignatureVerification)?;
        let ed_sig = EdSignature::from_bytes(&ed_sig_bytes);
        ed_vk
            .verify(message, &ed_sig)
            .map_err(|_| KassiberError::SignatureVerification)?;
        Ok(())
    }
}

impl HybridPublicKey {
    /// Hybrid KEM encapsulation: ML-KEM-768 + ephemeral X25519.
    ///
    /// Returns (shared_secret, ciphertext). The X25519 shared secret is NOT
    /// transmitted; the receiver recomputes it from `ephemeral_pub`.
    pub fn encrypt<R: CryptoRng>(&self, rng: &mut R) -> Result<(Vec<u8>, HybridCiphertext)> {
        let (pq_shared, pq_ct) = self.pq_encap.encapsulate(rng)?;
        let ephemeral = X25519KeyPair::generate(rng);
        let classical_pub = X25519PublicKey::from(self.classical_pub);
        let classical_shared = ephemeral.secret.diffie_hellman(&classical_pub);
        let shared_secret = combine_hybrid_secrets(
            &pq_shared,
            classical_shared.as_bytes(),
            &ephemeral.public,
        );
        let ct = HybridCiphertext {
            pq_ct,
            ephemeral_pub: ephemeral.public,
        };
        Ok((shared_secret.to_vec(), ct))
    }
}

impl HybridSecretKey {
    /// Hybrid KEM decapsulation; recomputes the X25519 shared secret locally.
    pub fn decrypt(&self, ct: &HybridCiphertext) -> Result<Vec<u8>> {
        let kp = PostQuantumKeyPair {
            public: Vec::new(),
            secret: self.pq_decap.clone(),
        };
        let pq_shared = kp.decapsulate(&ct.pq_ct)?;
        let classical_pub = X25519PublicKey::from(ct.ephemeral_pub);
        let classical_shared = self.classical_secret.diffie_hellman(&classical_pub);
        Ok(combine_hybrid_secrets(&pq_shared, classical_shared.as_bytes(), &ct.ephemeral_pub).to_vec())
    }
}

/// HKDF combiner for the hybrid KEM shared secrets.
fn combine_hybrid_secrets(pq_shared: &[u8], classical_shared: &[u8], ephemeral_pub: &[u8; 32]) -> [u8; 32] {
    let mut ikm = Vec::with_capacity(pq_shared.len() + classical_shared.len());
    ikm.extend_from_slice(pq_shared);
    ikm.extend_from_slice(classical_shared);
    // Bind the ephemeral public key via the HKDF salt so the derived secret is
    // tied to this exact transcript.
    hkdf32(&ikm, ephemeral_pub, b"kassiber-v1-hybrid-kem")
}

impl Aes256GcmKey {
    /// Derive an AES-256-GCM key from a shared secret via HKDF-SHA-256.
    pub fn from_shared_secret(secret: &[u8]) -> Self {
        Self {
            key: hkdf32(secret, b"kassiber-aes-salt-v1", b"kassiber-aes-key-v1"),
        }
    }

    /// AEAD-encrypt; `aad` is authenticated but not encrypted.
    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<AesAead> {
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|e| KassiberError::Encryption(format!("AES key init: {:?}", e)))?;
        let mut nonce_bytes = [0u8; AES_NONCE_SIZE];
        rand::fill(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, Payload { msg: plaintext, aad })
            .map_err(|e| KassiberError::Encryption(format!("AES encrypt: {:?}", e)))?;
        let ct_len = ciphertext.len() - 16;
        let mut ct = vec![0u8; ct_len];
        ct.copy_from_slice(&ciphertext[..ct_len]);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&ciphertext[ct_len..]);
        Ok(AesAead {
            ciphertext: ct,
            nonce: nonce_bytes,
            tag,
        })
    }

    /// AEAD-decrypt; fails if the tag or AAD does not match.
    pub fn decrypt(&self, aead: &AesAead, aad: &[u8]) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|e| KassiberError::Decryption(format!("AES key init: {:?}", e)))?;
        let nonce = Nonce::from_slice(&aead.nonce);
        let mut full_ct = Vec::with_capacity(aead.ciphertext.len() + 16);
        full_ct.extend_from_slice(&aead.ciphertext);
        full_ct.extend_from_slice(&aead.tag);
        cipher
            .decrypt(nonce, Payload {
                msg: full_ct.as_ref(),
                aad,
            })
            .map_err(|e| KassiberError::Decryption(format!("AES decrypt: {:?}", e)))
    }
}

pub fn concat_hash(a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(a);
    hasher.update(b);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ml_kem_roundtrip() {
        let mut rng = rand::rng();
        let kp = PostQuantumKeyPair::generate_ml_kem768(&mut rng).unwrap();
        assert_eq!(kp.public.len(), 1184);
        assert_eq!(kp.secret.len(), 64);
        let pk = PostQuantumPublicKey {
            bytes: kp.public.clone(),
        };
        let (ss1, ct) = pk.encapsulate(&mut rng).unwrap();
        let ss2 = kp.decapsulate(&ct).unwrap();
        assert_eq!(ss1, ss2);
        assert_eq!(ss1.len(), 32);
    }

    #[test]
    fn test_ml_dsa65_sign_verify() {
        let mut rng = rand::rng();
        let kp = DualKeyPair::generate(&mut rng).unwrap();
        let (ml_dsa_pub, ed_pub) = kp.verifying_keys();
        assert_eq!(ml_dsa_pub.len(), 1952);
        let sig = kp.sign(b"kassiber").unwrap();
        sig.verify(b"kassiber", &ml_dsa_pub, &ed_pub).unwrap();
        // Wrong message must fail.
        assert!(sig.verify(b"forged", &ml_dsa_pub, &ed_pub).is_err());
        // Wrong key must fail.
        let other = DualKeyPair::generate(&mut rng).unwrap();
        let (other_ml, _) = other.verifying_keys();
        assert!(sig.verify(b"kassiber", &other_ml, &ed_pub).is_err());
    }

    #[test]
    fn test_hybrid_kem_roundtrip() {
        let mut rng = rand::rng();
        let kp = HybridKeyPair::generate(&mut rng).unwrap();
        let pk = kp.public_key();
        let (secret, ct) = pk.encrypt(&mut rng).unwrap();
        assert_eq!(secret.len(), 32);
        let sk = kp.secret_key();
        let decrypted = sk.decrypt(&ct).unwrap();
        assert_eq!(secret, decrypted);
    }

    #[test]
    fn test_aes_gcm_roundtrip() {
        let key = Aes256GcmKey::from_shared_secret(b"shared secret");
        let encrypted = key.encrypt(b"Hello KASSIBER", b"aad").unwrap();
        let decrypted = key.decrypt(&encrypted, b"aad").unwrap();
        assert_eq!(b"Hello KASSIBER".to_vec(), decrypted);
    }

    #[test]
    fn test_aes_gcm_aad_mismatch_rejected() {
        let key = Aes256GcmKey::from_shared_secret(b"shared secret");
        let encrypted = key.encrypt(b"Hello KASSIBER", b"correct aad").unwrap();
        assert!(key.decrypt(&encrypted, b"wrong aad").is_err());
        // Empty AAD vs. non-empty AAD must also differ.
        let encrypted2 = key.encrypt(b"Hello KASSIBER", b"").unwrap();
        assert!(key.decrypt(&encrypted2, b"non-empty").is_err());
        assert_eq!(key.decrypt(&encrypted2, b"").unwrap(), b"Hello KASSIBER");
    }
}
