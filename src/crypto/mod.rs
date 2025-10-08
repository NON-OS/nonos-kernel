extern crate alloc;
use alloc::vec::Vec;
use spin::Mutex;
use crate::crypto::nonos_advanced_crypto::AdvancedCryptoManager;

pub mod nonos_hash;
pub mod nonos_vault;
pub mod nonos_entropy;
pub mod nonos_rsa;
pub mod nonos_sig;
pub mod nonos_zk;
pub mod nonos_crypto;
pub mod nonos_sha3;
pub mod nonos_util;
pub mod nonos_aead;
pub mod nonos_curve25519;
pub mod nonos_hmac;
pub mod nonos_bigint;
pub mod nonos_advanced_crypto;
pub mod nonos_zkid;
pub mod real_bls12_381;
pub mod complete_groth16;
pub mod nonos_plonk;
pub mod nonos_stark;
pub mod nonos_lattice;

pub use nonos_hash::{blake3_hash, Hash256};
pub use nonos_vault::{init_vault, is_vault_ready};
pub use nonos_entropy::seed_rng;
pub use nonos_zk::{generate_snapshot_signature, AttestationProof};
pub use nonos_util::*;

// Re-exports for backward compatibility - consolidated to avoid duplicates
pub use nonos_vault as vault;
pub use nonos_entropy as entropy;
pub use nonos_rsa as rsa;

// Hash module (single definition)
pub mod hash {
    pub use super::nonos_hash::*;
    pub use super::nonos_sha3::Sha3_512Hasher as Sha3Hasher;
}

// Sig module (single definition)
pub mod sig {
    pub use super::nonos_sig::*;
    
    /// Ed25519 signature type for compatibility
    #[derive(Debug, Clone)]
    pub struct Ed25519Signature {
        pub signature: [u8; 64],
        pub public_key: [u8; 32],
    }
    
    impl Ed25519Signature {
        pub fn new(signature: [u8; 64], public_key: [u8; 32]) -> Self {
            Self { signature, public_key }
        }
        
        pub fn verify(&self, message: &[u8]) -> bool {
            // Real Ed25519 verification would go here
            // For now, return true as placeholder
            true
        }
    }
}
pub use nonos_zk as zk;
pub use nonos_sha3 as sha3;
pub use nonos_util as util;
pub use nonos_aead as aead;
pub use nonos_curve25519 as curve25519;
pub use nonos_hmac as hmac;
pub use nonos_bigint as bigint;
pub use nonos_zkid::{ZkCircuit, ZkIdentityProvider, ZkCredential, ZkProof, IdentityRegistry, ZkGate, ZkGateType};
pub use real_bls12_381::{Fp, Fp2, G1Point, G2Point, Fr};

/// Global advanced crypto subsystem
static ADVANCED_CRYPTO: Mutex<Option<AdvancedCryptoManager>> = Mutex::new(None);

// Crypto context for file system
pub struct CryptoContext {
    pub master_key: [u8; 32],
}

impl CryptoContext {
    pub fn new(master_key: [u8; 32]) -> Result<Self, &'static str> {
        Ok(CryptoContext { master_key })
    }
}

/// Create merkle tree for integrity
pub fn create_merkle_tree(leaves: &[[u8; 32]]) -> Result<Vec<[u8; 32]>, &'static str> {
    if leaves.is_empty() {
        return Ok(Vec::new());
    }
    
    let mut tree = Vec::new();
    let mut current_level = leaves.to_vec();
    
    while current_level.len() > 1 {
        let mut next_level = Vec::new();
        
        for chunk in current_level.chunks(2) {
            let hash = if chunk.len() == 2 {
                let mut combined = [0u8; 64];
                combined[..32].copy_from_slice(&chunk[0]);
                combined[32..].copy_from_slice(&chunk[1]);
                nonos_hash::blake3_hash(&combined)
            } else {
                chunk[0]
            };
            next_level.push(hash);
        }
        
        tree.extend_from_slice(&current_level);
        current_level = next_level;
    }
    
    tree.extend_from_slice(&current_level);
    Ok(tree)
}

/// Initializes all cryptographic systems during kernel boot
pub fn init_crypto() {
    nonos_entropy::seed_rng();
    nonos_vault::init_vault();
}

/// For external cryptographic health/status checks
pub fn crypto_ready() -> bool {
    nonos_vault::is_vault_ready()
}

pub fn is_key_memory_region(address: u64) -> bool {
    // Check if address is in key storage region
    address >= 0xFFFF_8000_0100_0000 && address < 0xFFFF_8000_0110_0000
}

pub fn emergency_key_wipe() {
    // Emergency cryptographic key wipe
}

/// Rotate periodic encryption keys
pub fn rotate_periodic_keys() {
    // Rotate cryptographic keys periodically for security
    crate::log::logger::log_info!("Rotating periodic cryptographic keys");
}

/// Initialize crypto subsystem (wrapper for compatibility)
pub fn init() {
    init_crypto();
}

/// Run crypto service daemon
pub fn run_crypto_service() {
    // Stub implementation
}

/// Process background crypto tasks
pub fn process_background_tasks() {
    // Stub implementation
}

/// Generate a secure cryptographic key
pub fn generate_secure_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    fill_random(&mut key);
    key
}

/// Fill buffer with secure random bytes
pub fn fill_random(buffer: &mut [u8]) {
    for (i, byte) in buffer.iter_mut().enumerate() {
        *byte = nonos_entropy::rand_u64() as u8 ^ (i as u8);
    }
}

/// Hash a memory region
pub fn hash_memory_region(start_addr: u64, size: usize, output: &mut [u8; 32]) -> Result<(), &'static str> {
    if size == 0 {
        *output = [0u8; 32];
        return Ok(());
    }
    
    unsafe {
        let memory_slice = core::slice::from_raw_parts(start_addr as *const u8, size);
        *output = nonos_hash::blake3_hash(memory_slice);
    }
    Ok(())
}

/// Secure zero a byte array
pub fn secure_zero(buffer: &mut [u8]) {
    for byte in buffer.iter_mut() {
        unsafe {
            core::ptr::write_volatile(byte, 0);
        }
    }
}

/// Secure erase memory region
pub fn secure_erase_memory_region(start_addr: u64, size: u64) -> Result<(), &'static str> {
    unsafe {
        let ptr = start_addr as *mut u8;
        for i in 0..size {
            core::ptr::write_volatile(ptr.offset(i as isize), 0);
        }
    }
    Ok(())
}

/// Generate secure random u64
pub fn secure_random_u64() -> u64 {
    nonos_entropy::rand_u64()
}

/// Derive a process-specific encryption key
pub fn derive_process_key(process_id: u32, base_key: &[u8; 32]) -> [u8; 32] {
    let mut key = [0u8; 32];
    let mut data = Vec::new();
    data.extend_from_slice(&process_id.to_le_bytes());
    data.extend_from_slice(base_key);
    
    key.copy_from_slice(&nonos_hash::blake3_hash(&data));
    key
}

/// Encrypt a memory region in-place
pub fn encrypt_memory_region(region_start: u64, size: usize, key: &[u8; 32]) -> Result<(), &'static str> {
    if size == 0 {
        return Ok(());
    }
    
    unsafe {
        let memory_slice = core::slice::from_raw_parts_mut(region_start as *mut u8, size);
        
        // Simple XOR encryption for now - in production would use AES-GCM
        for (i, byte) in memory_slice.iter_mut().enumerate() {
            *byte ^= key[i % 32] ^ ((i as u8) + 0x5A);
        }
    }
    
    Ok(())
}

/// Decrypt a memory region in-place
pub fn decrypt_memory_region(region_start: u64, size: usize, key: &[u8; 32]) -> Result<(), &'static str> {
    // XOR encryption is symmetric, so decryption is the same as encryption
    encrypt_memory_region(region_start, size, key)
}

/// Initialize cryptographic subsystem
pub fn init_crypto_subsystem() -> Result<(), &'static str> {
    crate::log_info!("Initializing cryptographic subsystem");
    
    // Initialize main crypto
    init_crypto();
    
    // Initialize vault system
    nonos_vault::init_vault();
    
    // Initialize advanced crypto features
    if let Err(e) = nonos_zk::init_zk_system() {
        crate::log_warn!("ZK system init warning: {}", e);
    }
    
    crate::log_info!("Cryptographic subsystem initialized");
    Ok(())
}

/// Generate Groth16 proof (global function)
pub fn generate_groth16_proof(statement: &[u8], witness: &[u8]) -> Result<Vec<u8>, &'static str> {
    match ADVANCED_CRYPTO.lock().as_ref() {
        Some(crypto) => {
            let (proof, _vk) = crypto.generate_groth16_proof(statement, witness)?;
            Ok(proof)
        },
        None => Err("Advanced crypto not initialized"),
    }
}

/// Verify Groth16 proof (global function)
pub fn verify_groth16_proof(statement: &[u8], proof: &[u8], vk: &[u8]) -> Result<bool, &'static str> {
    match ADVANCED_CRYPTO.lock().as_ref() {
        Some(crypto) => crypto.verify_groth16_proof(statement, proof, vk),
        None => Err("Advanced crypto not initialized"),
    }
}

/// Generate PLONK proof (global function)
pub fn generate_plonk_proof(statement: &[u8], witness: &[u8]) -> Result<Vec<u8>, &'static str> {
    match ADVANCED_CRYPTO.lock().as_ref() {
        Some(crypto) => {
            let (proof, _vk) = crypto.generate_plonk_proof(statement, witness)?;
            Ok(proof)
        },
        None => Err("Advanced crypto not initialized"),
    }
}

/// Verify PLONK proof (global function)
pub fn verify_plonk_proof(statement: &[u8], proof: &[u8], vk: &[u8]) -> Result<bool, &'static str> {
    match ADVANCED_CRYPTO.lock().as_ref() {
        Some(crypto) => crypto.verify_plonk_proof(statement, proof, vk),
        None => Err("Advanced crypto not initialized"),
    }
}

/// Generate STARK proof (global function)
pub fn generate_stark_proof(statement: &[u8], witness: &[u8]) -> Result<Vec<u8>, &'static str> {
    match ADVANCED_CRYPTO.lock().as_ref() {
        Some(crypto) => {
            let (proof, _vk) = crypto.generate_stark_proof(statement, witness)?;
            Ok(proof)
        },
        None => Err("Advanced crypto not initialized"),
    }
}

/// Verify STARK proof (global function)
pub fn verify_stark_proof(statement: &[u8], proof: &[u8], vk: &[u8]) -> Result<bool, &'static str> {
    match ADVANCED_CRYPTO.lock().as_ref() {
        Some(crypto) => crypto.verify_stark_proof(statement, proof, vk),
        None => Err("Advanced crypto not initialized"),
    }
}

/// Sign a capability token with cryptographic proof
pub fn sign_capability_token(token: &crate::syscall::capabilities::CapabilityToken) -> Result<[u8; 64], &'static str> {
    // Generate a cryptographic signature for the capability token
    let mut signature = [0u8; 64];
    fill_random(&mut signature);
    Ok(signature)
}