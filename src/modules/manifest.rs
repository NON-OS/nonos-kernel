//! Module manifest definitions

pub struct ModuleManifest {
    pub name: &'static str,
    pub version: &'static str,
    pub author: &'static str,
    pub description: &'static str,
    pub module_type: ModuleType,
    pub auth_method: AuthMethod,
    pub memory_requirements: MemoryRequirements,
}

pub enum ModuleType {
    System,
    Driver,
    Application,
}

pub enum AuthMethod {
    VaultSignature,
    PublicKey,
}

pub struct MemoryRequirements {
    pub heap_size: u64,
    pub stack_size: u64,
}
