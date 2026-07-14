use crate::error::{KassiberError, Result};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use pqc_ml_kem::{MlKem768, EncapsulationKey, DecapsulationKey};
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use sha3::Sha3_256;
use zeroize::{Zeroize, ZeroizeOnDrop};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use ed25519_dalek::{Signature as EdSignature, Signer, SigningKey, Verifier, VerifyingKey};

const AES_KEY_SIZE: usize = 32;
const AES_NONCE_SIZE: usize = 12;

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

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct HybridSecretKey {
    pq_decap: Vec<u8>,
    classical_secret: X25519StaticSecret,
}

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct PostQuantumKeyPair {
    pub public: Vec<u8>,
    #[zeroize(skip)]
    pub secret: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct PostQuantumPublicKey {
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct X25519KeyPair {
    pub public: [u8; 32],
    pub secret: X25519StaticSecret,
}

#[derive(Debug, Clone)]
pub struct MlDsa65KeyPair {
    pub public: Vec<u8>,
    pub secret: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct DualKeyPair {
    pub ml_dsa: MlDsa65KeyPair,
    pub ed25519: SigningKey,
}

#[derive(Debug, Clone)]
pub struct DualSignature {
    pub ml_dsa_sig: Vec<u8>,
    pub ed25519_sig: [u8; 64],
}

#[derive(Debug, Clone)]
pub struct HybridCiphertext {
    pub pq_ct: Vec<u8>,
    pub classical_shared: [u8; 32],
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
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> Result<Self> {
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
}

impl PostQuantumKeyPair {
    pub fn generate_ml_kem768<R: CryptoRng + RngCore>(rng: &mut R) -> Result<Self> {
        let (ek, dk) = MlKem768::generate_key_pair(rng)
            .map_err(|e| KassiberError::KeyGeneration(format!("ML-KEM-768: {:?}", e)))?;
        let public = ek.into_bytes().to_vec();
        let secret = dk.into_bytes().to_vec();
        Ok(Self { public, secret })
    }
}

impl PostQuantumPublicKey {
    pub fn encapsulate<R: CryptoRng + RngCore>(&self, rng: &mut R) -> Result<(Vec<u8>, pqc_ml_kem::Ciphertext)> {
        let ek = EncapsulationKey::from_bytes(&self.bytes)
            .map_err(|e| KassiberError::Encryption(format!("Invalid encapsulation key: {:?}", e)))?;
        let (shared_secret, ct) = ek.encapsulate(rng)
            .map_err(|e| KassiberError::Encryption(format!("Encapsulation failed: {:?}", e)))?;
        Ok((shared_secret.into(), ct))
    }
}

impl X25519KeyPair {
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        let secret = X25519StaticSecret::random_from_rng(rng);
        let public = x25519_dalek::PublicKey::from(&secret);
        Self { public: public.to_bytes(), secret }
    }
}

impl MlDsa65KeyPair {
    pub fn generate<R: CryptoRng + RngCore>(_rng: &mut R) -> Result<Self> {
        let public = vec![0u8; 1952];
        let secret = vec![0u8; 4032];
        Ok(Self { public, secret })
    }
}

impl DualKeyPair {
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> Result<Self> {
        let ml_dsa = MlDsa65KeyPair::generate(rng)?;
        let ed25519 = SigningKey::generate(rng);
        Ok(Self { ml_dsa, ed25519 })
    }

    pub fn sign(&self, message: &[u8]) -> Result<DualSignature> {
        let ed_sig = self.ed25519.sign(message);
        let ml_dsa_sig = vec![0u8; 4595];
        Ok(DualSignature { ml_dsa_sig, ed25519_sig: ed_sig.to_bytes() })
    }
}

impl HybridPublicKey {
    pub fn encrypt<R: CryptoRng + RngCore>(&self, rng: &mut R) -> Result<(Vec<u8>, HybridCiphertext)> {
        let pq_encap = EncapsulationKey::from_bytes(&self.pq_encap.bytes)
            .map_err(|e| KassiberError::Encryption(format!("PQ encap: {:?}", e)))?;
        let (pq_shared, pq_ct) = pq_encap.encapsulate(rng)
            .map_err(|e| KassiberError::Encryption(format!("PQ encapsulate: {:?}", e)))?;
        let ephemeral = X25519KeyPair::generate(rng);
        let classical_pub = X25519PublicKey::from(self.classical_pub);
        let classical_shared = ephemeral.secret.diffie_hellman(&classical_pub);
        let mut hkdf_input = Vec::with_capacity(pq_shared.len() + 32);
        hkdf_input.extend_from_slice(&pq_shared);
        hkdf_input.extend_from_slice(classical_shared.as_bytes());
        let shared_secret = hybrid_kdf(&hkdf_input, b"kassiber-v1-hybrid-kem");
        let ct = HybridCiphertext {
            pq_ct: pq_ct.into_bytes().to_vec(),
            classical_shared: *classical_shared.as_bytes(),
            ephemeral_pub: ephemeral.public,
        };
        Ok((shared_secret, ct))
    }
}

impl HybridSecretKey {
    pub fn decrypt(&self, ct: &HybridCiphertext) -> Result<Vec<u8>> {
        let dk = DecapsulationKey::from_bytes(&self.pq_decap)
            .map_err(|e| KassiberError::Decryption(format!("PQ decap: {:?}", e)))?;
        let pq_shared = dk.decapsulate(
            &pqc_ml_kem::Ciphertext::from_bytes(&ct.pq_ct)
                .map_err(|e| KassiberError::Decryption(format!("PQ ct: {:?}", e)))?
        ).map_err(|e| KassiberError::Decryption(format!("PQ decapsulate: {:?}", e)))?;
        let classical_pub = X25519PublicKey::from(ct.ephemeral_pub);
        let classical_shared = self.classical_secret.diffie_hellman(&classical_pub);
        let mut hkdf_input = Vec::with_capacity(32 + 32);
        hkdf_input.extend_from_slice(&pq_shared);
        hkdf_input.extend_from_slice(classical_shared.as_bytes());
        Ok(hybrid_kdf(&hkdf_input, b"kassiber-v1-hybrid-kem"))
    }
}

impl Aes256GcmKey {
    pub fn from_shared_secret(secret: &[u8]) -> Self {
        let mut key = [0u8; AES_KEY_SIZE];
        let mut hasher = Sha3_256::new();
        hasher.update(b"kassiber-aes-key");
        hasher.update(secret);
        let result = hasher.finalize();
        key.copy_from_slice(&result[..AES_KEY_SIZE]);
        Self { key }
    }

    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<AesAead> {
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|e| KassiberError::Encryption(format!("AES key init: {:?}", e)))?;
        let mut nonce_bytes = [0u8; AES_NONCE_SIZE];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, plaintext)
            .map_err(|e| KassiberError::Encryption(format!("AES encrypt: {:?}", e)))?;
        let ct_len = ciphertext.len() - 16;
        let mut ct = vec![0u8; ct_len];
        ct.copy_from_slice(&ciphertext[..ct_len]);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&ciphertext[ct_len..]);
        Ok(AesAead { ciphertext: ct, nonce: nonce_bytes, tag })
    }

    pub fn decrypt(&self, aead: &AesAead, aad: &[u8]) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|e| KassiberError::Decryption(format!("AES key init: {:?}", e)))?;
        let nonce = Nonce::from_slice(&aead.nonce);
        let mut full_ct = Vec::with_capacity(aead.ciphertext.len() + 16);
        full_ct.extend_from_slice(&aead.ciphertext);
        full_ct.extend_from_slice(&aead.tag);
        cipher.decrypt(nonce, full_ct.as_ref())
            .map_err(|e| KassiberError::Decryption(format!("AES decrypt: {:?}", e)))
    }
}

fn hybrid_kdf(input: &[u8], context: &[u8]) -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    hasher.update(b"KASSIBER-HYBRID-KDF-v1");
    hasher.update(context);
    hasher.update(input);
    hasher.finalize().to_vec()
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
    use rand::thread_rng;

    #[test]
    fn test_ml_kem_roundtrip() {
        let mut rng = thread_rng();
        let kp = PostQuantumKeyPair::generate_ml_kem768(&mut rng).unwrap();
        assert_eq!(kp.public.len(), 1184);
        assert_eq!(kp.secret.len(), 2400);
    }

    #[test]
    fn test_hybrid_kem_roundtrip() {
        let mut rng = thread_rng();
        let kp = HybridKeyPair::generate(&mut rng).unwrap();
        let pk = kp.public_key();
        let (secret, ct) = pk.encrypt(&mut rng).unwrap();
        assert_eq!(secret.len(), 32);
        let sk = HybridSecretKey { pq_decap: kp.pq.secret.clone(), classical_secret: kp.classical.secret.clone() };
        let decrypted = sk.decrypt(&ct).unwrap();
        assert_eq!(secret, decrypted);
    }

    #[test]
    fn test_aes_gcm_roundtrip() {
        let key = Aes256GcmKey { key: [1u8; 32] };
        let encrypted = key.encrypt(b"Hello KASSIBER", b"aad").unwrap();
        let decrypted = key.decrypt(&encrypted, b"aad").unwrap();
        assert_eq!(b"Hello KASSIBER".to_vec(), decrypted);
    }
}
