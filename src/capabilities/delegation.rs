#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use crate::capabilities::{Capability, CapabilityToken};

/// Delegation allows a token to grant a subset of its rights to another module (with expiry).
#[derive(Debug, Clone)]
pub struct Delegation {
    pub delegator: u64,
    pub delegatee: u64,
    pub capabilities: Vec<Capability>,
    pub expires_at_ms: Option<u64>,
    pub parent_nonce: u64,
    pub signature: [u8; 64],
}

static NONCE_CTR: AtomicU64 = AtomicU64::new(1);

fn next_nonce() -> u64 {
    let t = crate::time::timestamp_millis();
    let c = NONCE_CTR.fetch_add(1, Ordering::Relaxed) & 0xFFFF_FFFF;
    (t << 32) ^ c
}

/// Create a delegation from a parent token to a delegatee module ID.
pub fn create_delegation(parent: &CapabilityToken, delegatee: u64, caps: &[Capability], ttl_ms: Option<u64>) -> Result<Delegation, &'static str> {
    let expiry = ttl_ms.map(|t| crate::time::timestamp_millis().saturating_add(t));
    let mut d = Delegation {
        delegator: parent.owner_module,
        delegatee,
        capabilities: caps.to_vec(),
        expires_at_ms: expiry,
        parent_nonce: parent.nonce,
        signature: [0u8; 64],
    };
    sign_delegation(&mut d, parent)?;
    Ok(d)
}

/// Sign delegation using parent token material.
pub fn sign_delegation(d: &mut Delegation, parent: &CapabilityToken) -> Result<(), &'static str> {
    let key = crate::capabilities::signing_key().ok_or("delegation: missing key")?;
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(&parent.nonce.to_le_bytes());
    hasher.update(&d.delegator.to_le_bytes());
    hasher.update(&d.delegatee.to_le_bytes());
    hasher.update(&crate::capabilities::caps_to_bits(&d.capabilities).to_le_bytes());
    hasher.update(&d.expires_at_ms.unwrap_or(0).to_le_bytes());
    let mac = hasher.finalize();
    d.signature.copy_from_slice(mac.as_bytes());
    Ok(())
}

/// Verify delegation signature matches parent token.
pub fn verify_delegation(d: &Delegation, parent: &CapabilityToken) -> bool {
    let key = crate::capabilities::signing_key();
    if key.is_none() { return false; }
    let mut hasher = blake3::Hasher::new_keyed(key.unwrap());
    hasher.update(&parent.nonce.to_le_bytes());
    hasher.update(&d.delegator.to_le_bytes());
    hasher.update(&d.delegatee.to_le_bytes());
    hasher.update(&crate::capabilities::caps_to_bits(&d.capabilities).to_le_bytes());
    hasher.update(&d.expires_at_ms.unwrap_or(0).to_le_bytes());
    let mac = hasher.finalize();
    &d.signature[..32] == &mac.as_bytes()[..32]
}
