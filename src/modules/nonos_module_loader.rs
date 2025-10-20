//! NØNOS Secure RAM-Only Module Loader & Registry

use alloc::{vec::Vec, collections::BTreeMap, string::String};
use spin::{RwLock, Mutex};
use crate::syscall::capabilities::CapabilityToken;
use crate::crypto::verify_ed25519;
use crate::crypto::blake3::blake3_hash;
use crate::memory::secure_erase;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonosModuleType {
    System = 0,
    Application = 1,
    Driver = 2,
    Service = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonosModuleState {
    Unloaded = 0,
    Loading = 1,
    Loaded = 2,
    Running = 3,
    Paused = 4,
    Stopping = 5,
    Stopped = 6,
    Failed = 7,
}

#[derive(Debug)]
pub struct NonosLoadedModule {
    pub module_id: u64,
    pub name: String,
    pub module_type: NonosModuleType,
    pub state: NonosModuleState,
    pub code: Vec<u8>,
    pub entry_point: Option<u64>,
    pub memory_base: Option<u64>,
    pub memory_size: usize,
    pub capabilities: Vec<CapabilityToken>,
    pub signature_verified: bool,
    pub hash: [u8; 32],
    pub load_time: u64,
}

#[derive(Debug)]
pub struct NonosModuleLoader {
    loaded_modules: RwLock<BTreeMap<u64, NonosLoadedModule>>,
    module_signatures: RwLock<BTreeMap<u64, [u8; 64]>>,
    next_module_id: Mutex<u64>,
    security_enabled: bool,
}

impl NonosModuleLoader {
    pub const fn new() -> Self {
        Self {
            loaded_modules: RwLock::new(BTreeMap::new()),
            module_signatures: RwLock::new(BTreeMap::new()),
            next_module_id: Mutex::new(1),
            security_enabled: true,
        }
    }

    /// Load and verify a module. All contents are RAM-only, wiped on unload.
    pub fn load_module(
        &self,
        name: &str,
        module_type: NonosModuleType,
        code: Vec<u8>,
        signature: &[u8; 64]
    ) -> Result<u64, &'static str> {
        // Cryptographic verification (Ed25519 + hash)
        let hash = blake3_hash(&code);
        if self.security_enabled && !verify_ed25519(&hash, signature)? {
            return Err("Invalid module signature");
        }

        let module_id = {
            let mut next_id = self.next_module_id.lock();
            let id = *next_id;
            *next_id += 1;
            id
        };

        let entry_point = if code.len() >= 8 {
            Some(u64::from_le_bytes([
                code[0], code[1], code[2], code[3],
                code[4], code[5], code[6], code[7]
            ]))
        } else {
            None
        };

        let module = NonosLoadedModule {
            module_id,
            name: String::from(name),
            module_type,
            state: NonosModuleState::Loaded,
            code,
            entry_point,
            memory_base: None,
            memory_size: 0,
            capabilities: Vec::new(),
            signature_verified: self.security_enabled,
            hash,
            load_time: self.get_timestamp(),
        };

        self.loaded_modules.write().insert(module_id, module);
        self.module_signatures.write().insert(module_id, *signature);

        Ok(module_id)
    }

    /// Securely erase and unload module. RAM-only, wiped after unload.
    pub fn unload_module(&self, module_id: u64) -> Result<(), &'static str> {
        let mut modules = self.loaded_modules.write();
        let module = modules.get_mut(&module_id).ok_or("Module not found")?;

        // Wipe code from RAM
        secure_erase(&mut module.code);

        // Remove from registry
        modules.remove(&module_id);
        self.module_signatures.write().remove(&module_id);

        Ok(())
    }

    pub fn start_module(&self, module_id: u64) -> Result<(), &'static str> {
        let mut modules = self.loaded_modules.write();
        let module = modules.get_mut(&module_id).ok_or("Module not found")?;
        if module.state != NonosModuleState::Loaded {
            return Err("Module not in loadable state");
        }
        module.state = NonosModuleState::Running;
        Ok(())
    }

    pub fn stop_module(&self, module_id: u64) -> Result<(), &'static str> {
        let mut modules = self.loaded_modules.write();
        let module = modules.get_mut(&module_id).ok_or("Module not found")?;
        if module.state != NonosModuleState::Running {
            return Err("Module not running");
        }
        module.state = NonosModuleState::Stopped;
        Ok(())
    }

    pub fn get_module_info(&self, module_id: u64) -> Result<NonosModuleInfo, &'static str> {
        let modules = self.loaded_modules.read();
        let module = modules.get(&module_id).ok_or("Module not found")?;
        Ok(NonosModuleInfo {
            module_id: module.module_id,
            name: module.name.clone(),
            module_type: module.module_type,
            state: module.state,
            memory_size: module.memory_size,
            signature_verified: module.signature_verified,
            hash: module.hash,
            load_time: module.load_time,
            capabilities_count: module.capabilities.len(),
        })
    }

    pub fn list_modules(&self) -> Vec<u64> {
        self.loaded_modules.read().keys().cloned().collect()
    }

    fn get_timestamp(&self) -> u64 {
        unsafe { core::arch::x86_64::_rdtsc() }
    }

    pub fn get_loaded_module_count(&self) -> usize {
        self.loaded_modules.read().len()
    }
}

#[derive(Debug)]
pub struct NonosModuleInfo {
    pub module_id: u64,
    pub name: String,
    pub module_type: NonosModuleType,
    pub state: NonosModuleState,
    pub memory_size: usize,
    pub signature_verified: bool,
    pub hash: [u8; 32],
    pub load_time: u64,
    pub capabilities_count: usize,
}

// Global module loader instance (RAM-only)
pub static NONOS_MODULE_LOADER: NonosModuleLoader = NonosModuleLoader::new();

// Convenience functions
pub fn load_module(
    name: &str,
    module_type: NonosModuleType,
    code: Vec<u8>,
    signature: &[u8; 64]
) -> Result<u64, &'static str> {
    NONOS_MODULE_LOADER.load_module(name, module_type, code, signature)
}

pub fn unload_module(module_id: u64) -> Result<(), &'static str> {
    NONOS_MODULE_LOADER.unload_module(module_id)
}

pub fn start_module(module_id: u64) -> Result<(), &'static str> {
    NONOS_MODULE_LOADER.start_module(module_id)
}

pub fn stop_module(module_id: u64) -> Result<(), &'static str> {
    NONOS_MODULE_LOADER.stop_module(module_id)
}

pub fn get_module_info(module_id: u64) -> Result<NonosModuleInfo, &'static str> {
    NONOS_MODULE_LOADER.get_module_info(module_id)
}

pub fn list_loaded_modules() -> Vec<u64> {
    NONOS_MODULE_LOADER.list_modules()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_load_and_erase() {
        let code = vec![1,2,3,4,5,6,7,8,9,10];
        let sig = [0u8; 64];
        let id = load_module("test", NonosModuleType::System, code.clone(), &sig).unwrap();
        assert_eq!(get_module_info(id).unwrap().name, "test");
        unload_module(id).unwrap();
        assert!(get_module_info(id).is_err());
    }
}
