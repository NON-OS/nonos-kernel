#![no_std]

extern crate alloc;

use alloc::{string::String, vec::Vec, collections::BTreeMap};

/// Database of trusted kernel/user modules for module integrity enforcement
pub struct ModuleDB {
    trusted_modules: BTreeMap<String, [u8; 32]>, // name -> hash
    loaded_modules: Vec<String>,
}

static mut MODULE_DB: Option<ModuleDB> = None;

/// Initialize the module database
pub fn init() -> Result<(), &'static str> {
    unsafe {
        MODULE_DB = Some(ModuleDB {
            trusted_modules: BTreeMap::new(),
            loaded_modules: Vec::new(),
        });
    }
    Ok(())
}

/// Add a trusted module (name and hash)
pub fn add_trusted_module(name: &str, hash: [u8; 32]) {
    unsafe {
        if let Some(db) = MODULE_DB.as_mut() {
            db.trusted_modules.insert(name.into(), hash);
        }
    }
}

/// Mark a module as loaded
pub fn mark_module_loaded(name: &str) {
    unsafe {
        if let Some(db) = MODULE_DB.as_mut() {
            if !db.loaded_modules.contains(&name.into()) {
                db.loaded_modules.push(name.into());
            }
        }
    }
}

/// Check if a module is trusted
pub fn is_trusted_module(name: &str) -> bool {
    unsafe {
        if let Some(db) = MODULE_DB.as_ref() {
            db.trusted_modules.contains_key(name)
        } else {
            false
        }
    }
}

/// Check if a loaded module matches its trusted hash
pub fn verify_module(name: &str, hash: &[u8; 32]) -> bool {
    unsafe {
        if let Some(db) = MODULE_DB.as_ref() {
            db.trusted_modules.get(name).map_or(false, |h| h == hash)
        } else {
            false
        }
    }
}

/// List all loaded modules
pub fn get_loaded_modules() -> Vec<String> {
    unsafe {
        if let Some(db) = MODULE_DB.as_ref() {
            db.loaded_modules.clone()
        } else {
            Vec::new()
        }
    }
}
