// This file is part of the NONOS Operating Systems Kernel.
// 
//  Copyright (C) [2025] [NONOS]
//  
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU Affero General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//  
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
//  GNU Affero General Public License for more details.
//!
//! NØNOS Cryptography Subsystem Entrypoint
//!
//! Initializes and wires all cryptographic components: entropy, vault, hash, sig, zk.
//! Ensures that the ZeroState environment has a hardened root-of-trust and entropy pool.

pub mod vault;
pub mod hash;
pub mod sig;
pub mod entropy;
pub mod zk;

/// Initializes all cryptographic systems during kernel boot
pub fn init_crypto() {
    entropy::seed_rng();
    vault::init_vault();
    audit("[crypto] subsystem online");
}

/// Emits a centralized log from crypto layer
fn audit(msg: &str) {
    if let Some(logger) = crate::log_logger::try_get_logger() {
        logger.log(msg);
    }
}

/// For external cryptographic health/status checks
pub fn crypto_ready() -> bool {
    vault::is_vault_ready() && entropy::rand_u64() != 0
}

/// Exposed for testing hash function correctness
pub fn test_hash(input: &[u8]) -> [u8; 32] {
    hash::blake3_hash(input)
}

/// Utility: sign+verify signature roundtrip (dev only)
pub fn test_signature_roundtrip() -> bool {
    let message = b"test-signature";
    let keypair = vault::get_test_keypair();
    let sig = keypair.sign(message);
    sig.verify(&keypair.public, message).is_ok()
}
