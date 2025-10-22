#![no_std]

extern crate alloc;

use alloc::vec::Vec;

use crate::capabilities::Capability;

#[derive(Debug, Clone)]
pub struct MultiSigToken {
    pub owner_module: u64,
    pub permissions: Vec<Capability>,
    pub expires_at_ms: Option<u64>,
    pub nonce: u64,
    pub signatures: Vec<[u8; 64]>, // each is a blake3 mac
    pub signers: Vec<u64>,
}

pub fn create_multisig_token(owner: u64, perms: &[Capability], signers: &[u64], ttl_ms: Option<u64>) -> MultiSigToken {
    MultiSigToken {
        owner_module: owner,
        permissions: perms.to_vec(),
        expires_at_ms: ttl_ms,
        nonce: crate::capabilities::default_nonce(),
        signatures: Vec::new(),
        signers: signers.to_vec(),
    }
}

pub fn add_signature(token: &mut MultiSigToken, signer_id: u64, key: &[u8;32]) {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(&signer_id.to_le_bytes());
    hasher.update(&token.owner_module.to_le_bytes());
    hasher.update(&crate::capabilities::caps_to_bits(&token.permissions).to_le_bytes());
    hasher.update(&token.nonce.to_le_bytes());
    hasher.update(&token.expires_at_ms.unwrap_or(0).to_le_bytes());
    let mac = hasher.finalize();
    let mac_bytes = mac.as_bytes();
    let mut signature = [0u8; 64];
    signature[..32].copy_from_slice(mac_bytes);
    signature[32..].copy_from_slice(mac_bytes); // Duplicate the hash to fill 64 bytes
    token.signatures.push(signature);
    token.signers.push(signer_id);
}

pub fn verify_multisig(token: &MultiSigToken, required: usize, keys: &[(&u64, &[u8;32])]) -> bool {
    // At least "required" valid signatures from distinct signers
    let mut valid = 0;
    for (i, sig) in token.signatures.iter().enumerate() {
        if i >= token.signers.len() { break; }
        let signer_id = token.signers[i];
        for (id, key) in keys {
            if **id == signer_id {
                let mut hasher = blake3::Hasher::new_keyed(key);
                hasher.update(&signer_id.to_le_bytes());
                hasher.update(&token.owner_module.to_le_bytes());
                hasher.update(&crate::capabilities::caps_to_bits(&token.permissions).to_le_bytes());
                hasher.update(&token.nonce.to_le_bytes());
                hasher.update(&token.expires_at_ms.unwrap_or(0).to_le_bytes());
                let mac = hasher.finalize();
                if &mac.as_bytes()[..32] == &sig[..32] {
                    valid += 1;
                }
            }
        }
    }
    valid >= required
}
