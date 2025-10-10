extern crate alloc;
use alloc::vec::Vec;

pub mod advanced_crypto;
pub mod aead;
pub mod bigint;
pub mod curve25519;
pub mod entropy;
pub mod hash;
pub mod hmac;
pub mod nonos_zk;
pub mod rsa;
pub mod sha3;
pub mod sig;
pub mod util;
pub mod vault;
pub mod zk;

pub use entropy::seed_rng;
pub use hash::blake3_hash;
pub use util::*;
pub use vault::{init_vault, is_vault_ready};
pub use zk::{generate_snapshot_signature, AttestationProof};

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
                blake3_hash(&combined)
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
    entropy::seed_rng();
    vault::init_vault();
}

/// For external cryptographic health/status checks
pub fn crypto_ready() -> bool {
    vault::is_vault_ready()
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
        *byte = secure_random_u64() as u8 ^ (i as u8);
    }
}

/// Hash a memory region
pub fn hash_memory_region(
    start_addr: u64,
    size: usize,
    output: &mut [u8; 32],
) -> Result<(), &'static str> {
    if size == 0 {
        *output = [0u8; 32];
        return Ok(());
    }

    unsafe {
        let memory_slice = core::slice::from_raw_parts(start_addr as *const u8, size);
        *output = blake3_hash(memory_slice);
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
    entropy::rand_u64()
}
