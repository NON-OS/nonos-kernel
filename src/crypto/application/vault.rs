// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

#![no_std]
extern crate alloc;
use alloc::vec::Vec;
use crate::crypto::CryptoResult;
#[derive(Debug, Clone, Default)]
pub struct VaultPublicKey {
    pub key_data: Vec<u8>,
    pub algorithm: VaultKeyAlgorithm,
}

#[derive(Debug, Clone, Default)]
pub enum VaultKeyAlgorithm {
    #[default]
    Ed25519,
    Rsa2048,
    Secp256k1,
}

impl VaultPublicKey {
    pub fn new(key_data: Vec<u8>, algorithm: VaultKeyAlgorithm) -> Self {
        Self { key_data, algorithm }
    }

    pub fn from_ed25519(public_key: &[u8]) -> Self {
        Self {
            key_data: public_key.to_vec(),
            algorithm: VaultKeyAlgorithm::Ed25519,
        }
    }
}

use alloc::string::String;
use alloc::collections::BTreeMap;
use spin::RwLock;
use core::sync::atomic::{AtomicU32, Ordering};

static STRING_KEY_VAULT: RwLock<BTreeMap<String, Vec<u8>>> = RwLock::new(BTreeMap::new());
static NEXT_STRING_KEY_ID: AtomicU32 = AtomicU32::new(1000);
pub fn init_vault() -> CryptoResult<()> {
    STRING_KEY_VAULT.write().clear();
    Ok(())
}

pub fn store_key(key_id: &str, key: &[u8]) -> CryptoResult<()> {
    if key_id.is_empty() {
        return Err(crate::crypto::CryptoError::InvalidInput);
    }
    if key.is_empty() {
        return Err(crate::crypto::CryptoError::InvalidInput);
    }

    STRING_KEY_VAULT.write().insert(String::from(key_id), key.to_vec());
    Ok(())
}

pub fn retrieve_key(key_id: &str) -> CryptoResult<Vec<u8>> {
    if key_id.is_empty() {
        return Err(crate::crypto::CryptoError::InvalidInput);
    }

    STRING_KEY_VAULT
        .read()
        .get(key_id)
        .cloned()
        .ok_or(crate::crypto::CryptoError::InvalidInput)
}

pub fn delete_key(key_id: &str) -> CryptoResult<()> {
    if key_id.is_empty() {
        return Err(crate::crypto::CryptoError::InvalidInput);
    }

    let mut vault = STRING_KEY_VAULT.write();
    if let Some(mut key_data) = vault.remove(key_id) {
        for byte in key_data.iter_mut() {
            unsafe { core::ptr::write_volatile(byte, 0) };
        }
        core::sync::atomic::compiler_fence(Ordering::SeqCst);
    }
    Ok(())
}

pub fn list_keys() -> CryptoResult<Vec<alloc::string::String>> {
    let vault = STRING_KEY_VAULT.read();
    Ok(vault.keys().cloned().collect())
}

pub fn generate_random_bytes(buffer: &mut [u8]) -> CryptoResult<()> {
    for chunk in buffer.chunks_mut(8) {
        let random_u64 = generate_secure_u64()?;
        let bytes = random_u64.to_le_bytes();
        let copy_len = core::cmp::min(chunk.len(), 8);
        chunk[..copy_len].copy_from_slice(&bytes[..copy_len]);
    }
    Ok(())
}

fn generate_secure_u64() -> CryptoResult<u64> {
    for _ in 0..10 {
        if let Some(value) = rdrand_u64() {
            return Ok(value);
        }
    }

    let mut entropy = 0u64;

    unsafe {
        core::arch::asm!("rdtsc", out("rax") entropy, out("rdx") _);
    }

    let stack_addr = &entropy as *const u64 as u64;
    entropy ^= stack_addr;

    let cpuid_result = unsafe { core::arch::x86_64::__cpuid(1) };
    entropy ^= (cpuid_result.ecx as u64) << 32;

    let input_bytes = entropy.to_le_bytes();
    let hash = crate::crypto::blake3::blake3_hash(&input_bytes);
    let result = u64::from_le_bytes([
        hash[0], hash[1], hash[2], hash[3],
        hash[4], hash[5], hash[6], hash[7],
    ]);

    Ok(result)
}

fn rdrand_u64() -> Option<u64> {
    let mut result: u64;
    let success: u8;

    unsafe {
        core::arch::asm!(
            "rdrand {result}",
            "setc {success}",
            result = out(reg) result,
            success = out(reg_byte) success,
            options(nomem, nostack)
        );
    }

    if success != 0 {
        Some(result)
    } else {
        None
    }
}
pub fn random_u64() -> u64 {
    let mut bytes = [0u8; 8];
    let _ = generate_random_bytes(&mut bytes);
    u64::from_le_bytes(bytes)
}

pub fn allocate_secure_memory(size: usize) -> *mut u8 {
    crate::memory::allocator::allocate_aligned(size, 8).ok().map(|va| va.as_mut_ptr::<u8>()).unwrap_or(core::ptr::null_mut())
}

pub fn deallocate_secure_memory(ptr: *mut u8, _size: usize) {
    crate::memory::allocator::free_pages(x86_64::VirtAddr::from_ptr(ptr), 1).ok();
}

#[derive(Debug, Clone)]
pub struct KeyEntry {
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
    pub algorithm: VaultKeyAlgorithm,
    pub created_ms: u64,
}

static KEY_VAULT: RwLock<BTreeMap<u32, KeyEntry>> = RwLock::new(BTreeMap::new());

pub fn get_signing_key(key_id: u32) -> Option<[u8; 32]> {
    let vault = KEY_VAULT.read();
    vault.get(&key_id).and_then(|entry| {
        if entry.private_key.len() >= 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&entry.private_key[..32]);
            Some(key)
        } else {
            None
        }
    })
}

pub fn get_public_key(key_id: u32) -> Option<[u8; 32]> {
    let vault = KEY_VAULT.read();
    vault.get(&key_id).and_then(|entry| {
        if entry.public_key.len() >= 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&entry.public_key[..32]);
            Some(key)
        } else {
            None
        }
    })
}

pub fn store_keypair(key_id: u32, private_key: &[u8], public_key: &[u8], algorithm: VaultKeyAlgorithm) -> CryptoResult<()> {
    let entry = KeyEntry {
        private_key: private_key.to_vec(),
        public_key: public_key.to_vec(),
        algorithm,
        created_ms: crate::time::timestamp_millis(),
    };
    KEY_VAULT.write().insert(key_id, entry);
    Ok(())
}

pub fn generate_and_store_ed25519_keypair() -> CryptoResult<u32> {
    let keypair = crate::crypto::ed25519::KeyPair::generate();
    static NEXT_KEY_ID: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(1);
    let key_id = NEXT_KEY_ID.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
    store_keypair(key_id, &keypair.private, &keypair.public, VaultKeyAlgorithm::Ed25519)?;
    Ok(key_id)
}

pub fn delete_vault_key(key_id: u32) -> CryptoResult<()> {
    let mut vault = KEY_VAULT.write();
    if let Some(mut entry) = vault.remove(&key_id) {
        for byte in entry.private_key.iter_mut() {
            unsafe { core::ptr::write_volatile(byte, 0) };
        }
        for byte in entry.public_key.iter_mut() {
            unsafe { core::ptr::write_volatile(byte, 0) };
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

pub fn list_vault_keys() -> Vec<u32> {
    KEY_VAULT.read().keys().copied().collect()
}

pub fn zeroize_all_keys() {
    {
        let mut string_vault = STRING_KEY_VAULT.write();
        for (_, key_data) in string_vault.iter_mut() {
            for byte in key_data.iter_mut() {
                unsafe { core::ptr::write_volatile(byte, 0) };
            }
        }
        string_vault.clear();
    }

    {
        let mut vault = KEY_VAULT.write();
        for (_, entry) in vault.iter_mut() {
            for byte in entry.private_key.iter_mut() {
                unsafe { core::ptr::write_volatile(byte, 0) };
            }
            for byte in entry.public_key.iter_mut() {
                unsafe { core::ptr::write_volatile(byte, 0) };
            }
        }
        vault.clear();
    }

    core::sync::atomic::compiler_fence(Ordering::SeqCst);
}
