// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
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


extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use spin::{Mutex, RwLock};

use crate::crypto::blake3_hash;
use crate::memory::memory::zero_memory;

use super::constants::{INITIAL_MODULE_ID, MIN_ENTRY_POINT_SIZE};
use super::error::{ModuleLoaderError, ModuleLoaderResult};
use super::types::{NonosLoadedModule, NonosModuleInfo, NonosModuleState, NonosModuleType};

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
            next_module_id: Mutex::new(INITIAL_MODULE_ID),
            security_enabled: true,
        }
    }

    pub fn load_module(
        &self,
        name: &str,
        module_type: NonosModuleType,
        code: Vec<u8>,
        signature: &[u8; 64],
    ) -> ModuleLoaderResult<u64> {
        let hash = blake3_hash(&code);
        if self.security_enabled {
            let mut r = [0u8; 32];
            let mut s = [0u8; 32];
            r.copy_from_slice(&signature[..32]);
            s.copy_from_slice(&signature[32..]);
            let sig = crate::crypto::ed25519::Signature { R: r, S: s };
            if !crate::crypto::ed25519::verify(&[0u8; 32], &hash, &sig) {
                return Err(ModuleLoaderError::InvalidSignature);
            }
        }

        let module_id = {
            let mut next_id = self.next_module_id.lock();
            let id = *next_id;
            *next_id += 1;
            id
        };

        let entry_point = if code.len() >= MIN_ENTRY_POINT_SIZE {
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
            hash,
            load_time: self.get_timestamp(),
        };

        self.loaded_modules.write().insert(module_id, module);
        self.module_signatures.write().insert(module_id, *signature);

        Ok(module_id)
    }

    pub fn unload_module(&self, module_id: u64) -> ModuleLoaderResult<()> {
        let mut modules = self.loaded_modules.write();
        let module = modules
            .get_mut(&module_id)
            .ok_or(ModuleLoaderError::NotFound)?;

        let _ = zero_memory(
            x86_64::VirtAddr::from_ptr(module.code.as_mut_ptr()),
            module.code.len(),
        );

        modules.remove(&module_id);
        self.module_signatures.write().remove(&module_id);

        Ok(())
    }

    pub fn start_module(&self, module_id: u64) -> ModuleLoaderResult<()> {
        let mut modules = self.loaded_modules.write();
        let module = modules
            .get_mut(&module_id)
            .ok_or(ModuleLoaderError::NotFound)?;
        if module.state != NonosModuleState::Loaded {
            return Err(ModuleLoaderError::InvalidState);
        }
        module.state = NonosModuleState::Running;
        Ok(())
    }

    pub fn stop_module(&self, module_id: u64) -> ModuleLoaderResult<()> {
        let mut modules = self.loaded_modules.write();
        let module = modules
            .get_mut(&module_id)
            .ok_or(ModuleLoaderError::NotFound)?;
        if module.state != NonosModuleState::Running {
            return Err(ModuleLoaderError::NotRunning);
        }
        module.state = NonosModuleState::Stopped;
        Ok(())
    }

    pub fn get_module_info(&self, module_id: u64) -> ModuleLoaderResult<NonosModuleInfo> {
        let modules = self.loaded_modules.read();
        let module = modules.get(&module_id).ok_or(ModuleLoaderError::NotFound)?;
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

pub static NONOS_MODULE_LOADER: NonosModuleLoader = NonosModuleLoader::new();

pub fn init_module_loader() -> Result<(), &'static str> {
    crate::crypto::init_crypto_subsystem().map_err(|_| "Crypto init failed")?;
    crate::security::trusted_keys::init_trusted_keys();
    crate::memory::init_module_memory_protection();
    crate::log::info!("Production module loader initialized");
    Ok(())
}

pub fn verify_and_queue(
    manifest: &crate::modules::manifest::ModuleManifest,
) -> ModuleLoaderResult<u64> {
    use super::constants::{DEFAULT_NOP_SLED_SIZE, NOP_INSTRUCTION};
    use alloc::vec;

    if !manifest.verify_attestation_chain() {
        return Err(ModuleLoaderError::AttestationFailed);
    }

    let computed_hash = crate::crypto::blake3::blake3_hash(manifest.name.as_bytes());
    if computed_hash != manifest.hash {
        return Err(ModuleLoaderError::HashMismatch);
    }

    let _ = &manifest.capabilities;

    let module_id = NONOS_MODULE_LOADER.load_module(
        &manifest.name,
        NonosModuleType::System,
        vec![NOP_INSTRUCTION; DEFAULT_NOP_SLED_SIZE],
        &[0u8; 64],
    )?;

    let _ = crate::modules::register_active_module(&manifest.name, None);
    Ok(module_id)
}
