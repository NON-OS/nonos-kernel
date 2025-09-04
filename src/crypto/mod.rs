extern crate alloc;
use alloc::vec::Vec;

pub mod hash;
pub mod vault;
pub mod entropy;
pub mod sig;
pub mod zk;
pub mod advanced_crypto;
pub mod sha3;
pub mod util;
pub mod nonos_zk;

pub use hash::blake3_hash;
pub use vault::{init_vault, is_vault_ready};
pub use entropy::seed_rng;
pub use util::*;

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
