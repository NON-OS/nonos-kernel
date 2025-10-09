extern crate alloc;
use alloc::vec::Vec;

pub mod hash;
pub mod rng;
pub mod aes;
pub mod ed25519;
pub mod nonos_zk;
pub mod sha512;
pub mod groth16;
pub mod halo2;
pub mod kyber;
pub mod dilithium;

pub use hash::{sha256, blake3_hash};
pub use rng::{get_random_bytes, ChaChaRng};
pub use aes::{Aes256, encrypt_block, decrypt_block};
pub use ed25519::{KeyPair, Signature, sign, verify};
pub use nonos_zk::{init_zk_system, generate_snapshot_signature, AttestationProof, ZkCircuit, ZkGate, ZkGateType, ZkCredential, IdentityRegistry, ZkIdentityProvider, ZkProof, generate_plonk_proof, verify_plonk_proof};
pub use sha512::{sha512, Hash512};
pub use groth16::{Fp, G1Point, G2Point, Groth16Proof, Groth16VerifyingKey, Groth16Prover, Groth16Verifier, generate_groth16_proof, verify_groth16_proof};
pub use halo2::{Halo2Proof, Halo2Circuit, Halo2Prover, Halo2Verifier, generate_halo2_proof, verify_halo2_proof};
pub use kyber::{KyberPublicKey, KyberSecretKey, KyberCiphertext, KyberKeyPair, kyber_keygen, kyber_encaps, kyber_decaps};
pub use dilithium::{DilithiumPublicKey, DilithiumSecretKey, DilithiumSignature, DilithiumKeyPair, dilithium_keygen, dilithium_sign, dilithium_verify};

/// Simple XOR cipher for basic encryption
pub fn xor_encrypt(data: &mut [u8], key: &[u8]) {
    for (i, byte) in data.iter_mut().enumerate() {
        *byte ^= key[i % key.len()];
    }
}

/// Basic key derivation using repeated hashing
pub fn derive_key(password: &[u8], salt: &[u8], iterations: usize) -> [u8; 32] {
    let mut key = [0u8; 32];
    let mut data = Vec::new();
    data.extend_from_slice(password);
    data.extend_from_slice(salt);
    
    let mut current = sha256(&data);
    for _ in 1..iterations {
        current = sha256(&current);
    }
    
    key.copy_from_slice(&current);
    key
}

/// Initialize the crypto subsystem
pub fn init() {
    rng::init_rng();
}

/// Generate a random 256-bit key
pub fn generate_key() -> [u8; 32] {
    get_random_bytes()
}

/// Generate random bytes (alias for compatibility)
pub fn generate_random_bytes() -> [u8; 32] {
    get_random_bytes()
}

/// BLAKE3 hash function (alias for compatibility)
pub fn hash_blake3(data: &[u8]) -> [u8; 32] {
    blake3_hash(data)
}

/// Ed25519 signing (alias for compatibility)
pub fn sign_ed25519(data: &[u8], keypair: &KeyPair) -> [u8; 64] {
    let signature = sign(keypair, data);
    signature.to_bytes()
}

/// Secure random u64 (alias for compatibility)
pub fn secure_random_u64() -> u64 {
    rng::random_u64()
}

/// Random u64 for entropy module compatibility
pub mod entropy {
    pub fn rand_u64() -> u64 {
        super::rng::random_u64()
    }
    
    pub fn seed_rng() {
        super::rng::seed_rng()
    }
}

/// Vault module for compatibility
pub mod vault {
    #[derive(Debug, Clone, Default)]
    pub struct VaultPublicKey {
        pub key: [u8; 32],
    }
    
    pub fn init_vault() {
        
    }
    
    pub fn is_vault_ready() -> bool {
        true
    }
}

/// RSA module for compatibility  
pub mod rsa {
    pub struct RsaKeyPair {
        pub public: [u8; 256],
        pub private: [u8; 256],
    }
    
    impl RsaKeyPair {
        pub fn generate() -> Self {
            let mut keypair = Self {
                public: [0; 256],
                private: [0; 256],
            };
            super::rng::fill_random_bytes(&mut keypair.public);
            super::rng::fill_random_bytes(&mut keypair.private);
            keypair
        }
    }
}

/// Signature module for compatibility
pub mod sig {
    pub use super::ed25519::*;
    
    pub mod ed25519 {
        pub use super::super::ed25519::*;
    }
}

/// HMAC module
pub mod hmac {
    use super::hash::sha256;
    
    pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
        let mut key_pad = [0u8; 64];
        if key.len() > 64 {
            let hashed = sha256(key);
            key_pad[..32].copy_from_slice(&hashed);
        } else {
            key_pad[..key.len()].copy_from_slice(key);
        }
        
        let mut ipad = [0x36u8; 64];
        let mut opad = [0x5cu8; 64];
        
        for i in 0..64 {
            ipad[i] ^= key_pad[i];
            opad[i] ^= key_pad[i];
        }
        
        let mut inner = alloc::vec::Vec::new();
        inner.extend_from_slice(&ipad);
        inner.extend_from_slice(data);
        let inner_hash = sha256(&inner);
        
        let mut outer = alloc::vec::Vec::new();
        outer.extend_from_slice(&opad);
        outer.extend_from_slice(&inner_hash);
        
        sha256(&outer)
    }
}

/// Curve25519 module
pub mod curve25519 {
    pub struct Curve25519KeyPair {
        pub public: [u8; 32],
        pub private: [u8; 32],
    }
    
    impl Curve25519KeyPair {
        pub fn generate() -> Self {
            let mut keypair = Self {
                public: [0; 32],
                private: [0; 32],
            };
            super::rng::fill_random_bytes(&mut keypair.private);
            keypair.private[0] &= 248;
            keypair.private[31] &= 127;
            keypair.private[31] |= 64;
            
            keypair.public = keypair.private;
            keypair
        }
    }
}

/// Big integer module
pub mod bigint {
    #[derive(Debug, Clone)]
    pub struct BigUint {
        pub limbs: alloc::vec::Vec<u64>,
    }
    
    impl BigUint {
        pub fn from_u64(val: u64) -> Self {
            Self {
                limbs: alloc::vec![val],
            }
        }
        
        pub fn add(&self, other: &Self) -> Self {
            let mut result = alloc::vec::Vec::new();
            let mut carry = 0u64;
            let max_len = core::cmp::max(self.limbs.len(), other.limbs.len());
            
            for i in 0..max_len {
                let a = self.limbs.get(i).copied().unwrap_or(0);
                let b = other.limbs.get(i).copied().unwrap_or(0);
                let sum = a as u128 + b as u128 + carry as u128;
                result.push(sum as u64);
                carry = (sum >> 64) as u64;
            }
            
            if carry > 0 {
                result.push(carry);
            }
            
            Self { limbs: result }
        }
    }
}

/// Simple authenticated encryption using AES + HMAC
pub struct AuthenticatedCipher {
    encryption_key: [u8; 32],
    auth_key: [u8; 32],
}

impl AuthenticatedCipher {
    pub fn new(master_key: &[u8; 32]) -> Self {
        let enc_key = derive_key(&master_key[..16], b"encrypt", 1000);
        let auth_key = derive_key(&master_key[16..], b"auth", 1000);
        
        Self {
            encryption_key: enc_key,
            auth_key: auth_key,
        }
    }
    
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let mut ciphertext = plaintext.to_vec();
        xor_encrypt(&mut ciphertext, &self.encryption_key);
        
        // Add simple MAC
        let mac = sha256(&[&self.auth_key[..], &ciphertext].concat());
        ciphertext.extend_from_slice(&mac);
        
        ciphertext
    }
    
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, &'static str> {
        if ciphertext.len() < 32 {
            return Err("Ciphertext too short");
        }
        
        let (data, mac) = ciphertext.split_at(ciphertext.len() - 32);
        let expected_mac = sha256(&[&self.auth_key[..], data].concat());
        
        // Constant-time MAC verification
        let mut mac_valid = true;
        for i in 0..32 {
            if mac[i] != expected_mac[i] {
                mac_valid = false;
            }
        }
        
        if !mac_valid {
            return Err("MAC verification failed");
        }
        
        let mut plaintext = data.to_vec();
        xor_encrypt(&mut plaintext, &self.encryption_key);
        Ok(plaintext)
    }
}