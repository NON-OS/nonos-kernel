use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use spin::{Mutex, RwLock};

#[derive(Debug)]
pub struct NonosVault {
    master_key: RwLock<Option<[u8; 64]>>,
    derived_keys: RwLock<BTreeMap<u64, Vec<u8>>>,
    entropy_pool: Mutex<[u8; 4096]>,
    pool_index: Mutex<usize>,
    initialized: RwLock<bool>,
}

impl NonosVault {
    pub const fn new() -> Self {
        Self {
            master_key: RwLock::new(None),
            derived_keys: RwLock::new(BTreeMap::new()),
            entropy_pool: Mutex::new([0u8; 4096]),
            pool_index: Mutex::new(0),
            initialized: RwLock::new(false),
        }
    }

    pub fn initialize(&self) -> Result<(), &'static str> {
        // Collect entropy
        self.collect_entropy()?;

        // Generate master key
        let master_key = self.generate_master_key()?;
        *self.master_key.write() = Some(master_key);
        *self.initialized.write() = true;

        Ok(())
    }

    pub fn is_initialized(&self) -> bool {
        *self.initialized.read()
    }

    pub fn derive_key(&self, context: &str, key_length: usize) -> Result<Vec<u8>, &'static str> {
        if !self.is_initialized() {
            return Err("Vault not initialized");
        }

        let master_key = self.master_key.read();
        let master_key = master_key.as_ref().ok_or("No master key")?;

        let context_hash = self.hash_context(context);

        // Check if key already derived
        if let Some(existing_key) = self.derived_keys.read().get(&context_hash) {
            if existing_key.len() == key_length {
                return Ok(existing_key.clone());
            }
        }

        // Derive new key
        let derived_key = self.hkdf_expand(master_key, &context_hash, key_length)?;

        // Cache the derived key
        self.derived_keys.write().insert(context_hash, derived_key.clone());

        Ok(derived_key)
    }

    fn collect_entropy(&self) -> Result<(), &'static str> {
        let mut pool = self.entropy_pool.lock();
        let mut index = self.pool_index.lock();

        // Collect hardware entropy
        for i in 0..1024 {
            let entropy = self.get_hardware_entropy();
            pool[(*index + i) % 4096] ^= entropy;
        }

        *index = (*index + 1024) % 4096;
        Ok(())
    }

    fn generate_master_key(&self) -> Result<[u8; 64], &'static str> {
        let mut key = [0u8; 64];
        let pool = self.entropy_pool.lock();
        let index = self.pool_index.lock();

        // Generate key from entropy pool
        for i in 0..64 {
            key[i] = pool[(*index + i) % 4096];
        }

        Ok(key)
    }

    fn hash_context(&self, context: &str) -> u64 {
        let mut hash = 0u64;
        for byte in context.bytes() {
            hash = hash.wrapping_mul(31).wrapping_add(byte as u64);
        }
        hash
    }

    fn hkdf_expand(
        &self,
        key: &[u8; 64],
        info: &u64,
        length: usize,
    ) -> Result<Vec<u8>, &'static str> {
        let mut output = Vec::with_capacity(length);
        let info_bytes = info.to_le_bytes();

        for i in 0..length {
            let key_index = i % key.len();
            let info_index = i % info_bytes.len();
            output.push(key[key_index] ^ info_bytes[info_index] ^ (i as u8));
        }

        Ok(output)
    }

    fn get_hardware_entropy(&self) -> u8 {
        // Use RDTSC for timing entropy
        let tsc = unsafe { core::arch::x86_64::_rdtsc() };

        // Try RDRAND if available
        let mut rdrand = 0u32;
        let rdrand_success = unsafe { core::arch::x86_64::_rdrand32_step(&mut rdrand) };

        if rdrand_success == 1 {
            (tsc ^ rdrand as u64) as u8
        } else {
            tsc as u8
        }
    }

    pub fn secure_erase(&self) {
        // Clear master key
        if let Some(mut key) = self.master_key.try_write() {
            if let Some(ref mut k) = key.as_mut() {
                k.fill(0u8);
            }
            *key = None;
        }

        // Clear derived keys
        if let Some(mut keys) = self.derived_keys.try_write() {
            for (_, key) in keys.iter_mut() {
                key.fill(0);
            }
            keys.clear();
        }

        // Clear entropy pool
        if let Some(mut pool) = self.entropy_pool.try_lock() {
            pool.fill(0);
        }

        *self.initialized.write() = false;
    }
}

// Global vault instance
pub static NONOS_VAULT: NonosVault = NonosVault::new();

// Convenience functions
pub fn initialize_vault() -> Result<(), &'static str> {
    NONOS_VAULT.initialize()
}

pub fn derive_vault_key(context: &str, key_length: usize) -> Result<Vec<u8>, &'static str> {
    NONOS_VAULT.derive_key(context, key_length)
}

pub fn vault_initialized() -> bool {
    NONOS_VAULT.is_initialized()
}

pub fn secure_erase_vault() {
    NONOS_VAULT.secure_erase();
}
