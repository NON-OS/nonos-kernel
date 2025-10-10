#![no_std]

use crate::syscall::capabilities::CapabilityToken;
use alloc::{collections::BTreeMap, string::String, vec::Vec};
use spin::{Mutex, RwLock};

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

    pub fn load_module(
        &self,
        name: &str,
        module_type: NonosModuleType,
        code: Vec<u8>,
        signature: &[u8; 64],
    ) -> Result<u64, &'static str> {
        // Verify signature if security is enabled
        if self.security_enabled {
            if !self.verify_module_signature(&code, signature) {
                return Err("Invalid module signature");
            }
        }

        let module_id = {
            let mut next_id = self.next_module_id.lock();
            let id = *next_id;
            *next_id += 1;
            id
        };

        // Find entry point (simplified - just use first 8 bytes as entry point)
        let entry_point = if code.len() >= 8 {
            Some(u64::from_le_bytes([
                code[0], code[1], code[2], code[3], code[4], code[5], code[6], code[7],
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
            load_time: self.get_timestamp(),
        };

        self.loaded_modules.write().insert(module_id, module);
        self.module_signatures.write().insert(module_id, *signature);

        Ok(module_id)
    }

    pub fn unload_module(&self, module_id: u64) -> Result<(), &'static str> {
        let mut modules = self.loaded_modules.write();
        let module = modules.get_mut(&module_id).ok_or("Module not found")?;

        // Check if module can be unloaded
        if matches!(module.state, NonosModuleState::Running) {
            return Err("Cannot unload running module");
        }

        // Mark as stopped
        module.state = NonosModuleState::Stopped;

        // Remove from loaded modules
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

        // Simplified module execution - just change state
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
            load_time: module.load_time,
            capabilities_count: module.capabilities.len(),
        })
    }

    pub fn list_modules(&self) -> Vec<u64> {
        self.loaded_modules.read().keys().cloned().collect()
    }

    fn verify_module_signature(&self, _code: &[u8], _signature: &[u8; 64]) -> bool {
        // Simplified signature verification
        // In production, this would use proper cryptographic verification
        true
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
    pub load_time: u64,
    pub capabilities_count: usize,
}

// Global module loader instance
pub static NONOS_MODULE_LOADER: NonosModuleLoader = NonosModuleLoader::new();

// Convenience functions
pub fn load_module(
    name: &str,
    module_type: NonosModuleType,
    code: Vec<u8>,
    signature: &[u8; 64],
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
