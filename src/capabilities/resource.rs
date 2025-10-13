#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Clone)]
pub struct ResourceQuota {
    pub bytes: u64,
    pub ops: u64,
    pub expires_at_ms: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct ResourceToken {
    pub owner_module: u64,
    pub quota: ResourceQuota,
    pub nonce: u64,
    pub signature: [u8; 64],
}

static NONCE_CTR: AtomicU64 = AtomicU64::new(1);

fn next_nonce() -> u64 {
    let t = crate::time::timestamp_millis();
    let c = NONCE_CTR.fetch_add(1, Ordering::Relaxed) & 0xFFFF_FFFF;
    (t << 32) ^ c
}

pub fn create_resource_token(owner: u64, quota: ResourceQuota) -> Result<ResourceToken, &'static str> {
    let mut tok = ResourceToken {
        owner_module: owner,
        quota,
        nonce: next_nonce(),
        signature: [0u8; 64],
    };
    sign_resource_token(&mut tok)?;
    Ok(tok)
}

pub fn sign_resource_token(tok: &mut ResourceToken) -> Result<(), &'static str> {
    let key = crate::capabilities::signing_key().ok_or("resource: missing key")?;
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(&tok.owner_module.to_le_bytes());
    hasher.update(&tok.quota.bytes.to_le_bytes());
    hasher.update(&tok.quota.ops.to_le_bytes());
    hasher.update(&tok.quota.expires_at_ms.unwrap_or(0).to_le_bytes());
    hasher.update(&tok.nonce.to_le_bytes());
    let mac = hasher.finalize();
    tok.signature.copy_from_slice(mac.as_bytes());
    Ok(())
}

pub fn verify_resource_token(tok: &ResourceToken) -> bool {
    let key = crate::capabilities::signing_key();
    if key.is_none() { return false; }
    let mut hasher = blake3::Hasher::new_keyed(key.unwrap());
    hasher.update(&tok.owner_module.to_le_bytes());
    hasher.update(&tok.quota.bytes.to_le_bytes());
    hasher.update(&tok.quota.ops.to_le_bytes());
    hasher.update(&tok.quota.expires_at_ms.unwrap_or(0).to_le_bytes());
    hasher.update(&tok.nonce.to_le_bytes());
    let mac = hasher.finalize();
    &tok.signature[..32] == &mac.as_bytes()[..32]
}
