//! Module Trust Database
//!
//! Database of trusted kernel modules and their verification

use alloc::{collections::BTreeMap, string::String};
use spin::RwLock;

/// Module trust information
#[derive(Debug, Clone)]
pub struct ModuleTrust {
    pub name: String,
    pub hash: [u8; 32],
    pub trusted: bool,
}

/// Module database
static MODULE_DB: RwLock<BTreeMap<String, ModuleTrust>> = RwLock::new(BTreeMap::new());

/// Check if module is trusted
pub fn is_trusted_module(module_name: &str) -> bool {
    let db = MODULE_DB.read();
    if let Some(trust) = db.get(module_name) {
        trust.trusted
    } else {
        false // Unknown modules are not trusted
    }
}

/// Add trusted module
pub fn add_trusted_module(name: String, hash: [u8; 32]) {
    let trust = ModuleTrust {
        name: name.clone(),
        hash,
        trusted: true,
    };
    
    let mut db = MODULE_DB.write();
    db.insert(name, trust);
}