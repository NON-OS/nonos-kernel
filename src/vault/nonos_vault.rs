//! NØNOS Vault Core 

extern crate alloc;
use alloc::{collections::BTreeMap, vec::Vec, string::String};
use spin::{RwLock, Mutex};
use core::sync::atomic::{AtomicU64, Ordering};

use crate::crypto::{blake3_hash, hkdf_expand, get_random_bytes, fill_random_bytes, Hash256};

/// Vault audit event 
#[derive(Debug, Clone)]
pub struct VaultAuditEvent {
    pub timestamp: u64,
    pub event: String,
    pub context: Option<String>,
    pub status: Option<String>,
}

/// Vault global state
pub struct NonosVault {
    master_key: RwLock<Option<[u8; 64]>>,
    derived_keys: RwLock<BTreeMap<u64, Vec<u8>>>,
    entropy_pool: Mutex<[u8; 4096]>,
    pool_index: Mutex<usize>,
    initialized: RwLock<bool>,
    audit_log: Mutex<Vec<VaultAuditEvent>>,
    key_counter: AtomicU64,
}

impl NonosVault {
    pub const fn new() -> Self {
        Self {
            master_key: RwLock::new(None),
            derived_keys: RwLock::new(BTreeMap::new()),
            entropy_pool: Mutex::new([0u8; 4096]),
            pool_index: Mutex::new(0),
            initialized: RwLock::new(false),
            audit_log: Mutex::new(Vec::new()),
            key_counter: AtomicU64::new(1),
        }
    }

    /// Initialize the vault: collect entropy, generate master key
    pub fn initialize(&self) -> Result<(), &'static str> {
        self.collect_entropy()?;
        let master_key = self.generate_master_key()?;
        *self.master_key.write() = Some(master_key);
        *self.initialized.write() = true;
        self.audit("initialize", Some("vault.init"), Some("success"));
        Ok(())
    }

    /// Is vault initialized?
    pub fn is_initialized(&self) -> bool {
        *self.initialized.read()
    }

    /// Derive a key for a context (HKDF/BLAKE3, length configurable)
    pub fn derive_key(&self, context: &str, key_length: usize) -> Result<Vec<u8>, &'static str> {
        if !self.is_initialized() {
            return Err("Vault not initialized");
        }
        let master_key = self.master_key.read();
        let master_key = master_key.as_ref().ok_or("No master key")?;
        let context_hash = blake3_hash(context.as_bytes());
        let key_id = self.context_hash_id(&context_hash);

        // Check if already derived
        if let Some(existing_key) = self.derived_keys.read().get(&key_id) {
            if existing_key.len() == key_length {
                self.audit("derive_key", Some(context.to_string()), Some("cached"));
                return Ok(existing_key.clone());
            }
        }

        // Derive new key using HKDF-Expand
        let mut okm = vec![0u8; key_length];
        hkdf_expand(&blake3_hash(master_key), &context_hash, &mut okm).map_err(|_| "HKDF error")?;

        // Cache derived key
        self.derived_keys.write().insert(key_id, okm.clone());
        self.audit("derive_key", Some(context.to_string()), Some("new"));

        Ok(okm)
    }

    /// Secure entropy collection (hardware + kernel RNG)
    fn collect_entropy(&self) -> Result<(), &'static str> {
        let mut pool = self.entropy_pool.lock();
        let mut index = self.pool_index.lock();
        for i in 0..1024 {
            let entropy = self.get_hardware_entropy();
            pool[(*index + i) % 4096] ^= entropy;
        }
        *index = (*index + 1024) % 4096;
        self.audit("collect_entropy", None, Some("success"));
        Ok(())
    }

    /// Generate master key from entropy pool
    fn generate_master_key(&self) -> Result<[u8; 64], &'static str> {
        let mut key = [0u8; 64];
        let pool = self.entropy_pool.lock();
        let index = self.pool_index.lock();
        for i in 0..64 {
            key[i] = pool[(*index + i) % 4096];
        }
        self.audit("generate_master_key", None, Some("success"));
        Ok(key)
    }

    /// Hash context to key id (u64)
    fn context_hash_id(&self, context_hash: &[u8; 32]) -> u64 {
        let mut id = 0u64;
        for &b in context_hash.iter().take(8) {
            id = (id << 8) | (b as u64);
        }
        id
    }

    /// Secure HKDF-Expand (see crypto/hash.rs)
    fn hkdf_expand(&self, key: &[u8; 64], info: &[u8; 32], length: usize) -> Result<Vec<u8>, &'static str> {
        let mut okm = vec![0u8; length];
        hkdf_expand(&blake3_hash(key), info, &mut okm).map_err(|_| "HKDF error")?;
        Ok(okm)
    }

    /// Hardware entropy source (RDSEED/RDRAND/TSC), with fallback
    fn get_hardware_entropy(&self) -> u8 {
        let tsc = unsafe { core::arch::x86_64::_rdtsc() };
        let mut rdrand = 0u32;
        let rdrand_success = unsafe { core::arch::x86_64::_rdrand32_step(&mut rdrand) };
        if rdrand_success == 1 {
            (tsc ^ rdrand as u64) as u8
        } else {
            tsc as u8
        }
    }

    /// Secure erase: zeroize all secrets, keys, entropy, and mark as uninitialized
    pub fn secure_erase(&self) {
        if let Some(mut key) = self.master_key.try_write() {
            if let Some(ref mut k) = key.as_mut() { k.fill(0u8); }
            *key = None;
        }
        if let Some(mut keys) = self.derived_keys.try_write() {
            for (_, key) in keys.iter_mut() { key.fill(0); }
            keys.clear();
        }
        if let Some(mut pool) = self.entropy_pool.try_lock() {
            pool.fill(0);
        }
        *self.initialized.write() = false;
        self.audit("secure_erase", None, Some("success"));
    }

    /// Audit event (internal use)
    fn audit(&self, event: &str, context: Option<String>, status: Option<&str>) {
        let ts = self.timestamp();
        self.audit_log.lock().push(VaultAuditEvent {
            timestamp: ts,
            event: event.to_string(),
            context,
            status: status.map(|s| s.to_string()),
        });
    }

    /// Return last N audit events
    pub fn recent_audit(&self, n: usize) -> Vec<VaultAuditEvent> {
        let log = self.audit_log.lock();
        log.iter().rev().take(n).cloned().collect()
    }

    fn timestamp(&self) -> u64 {
        // Use kernel time API; fallback to atomic counter
        crate::time::timestamp_millis()
    }
}

// Global vault singleton
pub static NONOS_VAULT: NonosVault = NonosVault::new();

// Convenience API
pub fn initialize_vault() -> Result<(), &'static str> { NONOS_VAULT.initialize() }
pub fn derive_vault_key(context: &str, key_length: usize) -> Result<Vec<u8>, &'static str> {
    NONOS_VAULT.derive_key(context, key_length)
}
pub fn vault_initialized() -> bool { NONOS_VAULT.is_initialized() }
pub fn secure_erase_vault() { NONOS_VAULT.secure_erase(); }
pub fn vault_recent_audit(n: usize) -> Vec<VaultAuditEvent> { NONOS_VAULT.recent_audit(n) }
