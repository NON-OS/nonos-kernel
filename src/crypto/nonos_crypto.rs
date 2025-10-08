//! NØNOS Cryptography Subsystem Entrypoint
//!
//! Initializes and wires all cryptographic components: entropy, vault, hash, sig, zk.
//! Ensures that the ZeroState environment has a hardened root-of-trust and entropy pool.

// Import from parent crypto module
use crate::crypto::{nonos_vault, nonos_hash, nonos_sig, nonos_entropy, nonos_zk};

/// Initializes all cryptographic systems during kernel boot
pub fn init_crypto() {
    nonos_entropy::seed_rng();
    nonos_vault::init_vault();
    audit("[crypto] subsystem online");
}

/// Emits a centralized log from crypto layer
fn audit(msg: &str) {
    if let Some(logger) = crate::log::logger::try_get_logger() {
        logger.log(msg);
    }
}

/// For external cryptographic health/status checks
pub fn crypto_ready() -> bool {
    nonos_vault::is_vault_ready() && nonos_entropy::rand_u64() != 0
}

/// Exposed for testing hash function correctness
pub fn test_hash(input: &[u8]) -> [u8; 32] {
    nonos_hash::blake3_hash(input)
}

/// Utility: sign+verify signature roundtrip (dev only)
pub fn test_signature_roundtrip() -> bool {
    let message = b"test-signature";
    let keypair = nonos_vault::get_test_keypair();
    let sig = keypair.sign(message);
    sig.verify(&keypair.public, message).is_ok()
}
