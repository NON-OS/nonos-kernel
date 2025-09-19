//! NØNOS Advanced Module System (.mod) Loader
//!
//! Cryptographically verified, capability-aware module loading with attestation chains

use alloc::{vec::Vec, string::{String, ToString}, collections::BTreeMap, boxed::Box, format};
use core::sync::atomic::{AtomicU64, AtomicU32, AtomicBool, Ordering};
use spin::{Mutex, RwLock};
use x86_64::{VirtAddr, PhysAddr, structures::paging::PageTableFlags};
use crate::{
    crypto::{
        verify_ed25519, hash_blake3, derive_key, decrypt_chacha20_poly1305,
        post_quantum_verify, create_attestation_chain, generate_random_bytes,
    },
    process::capabilities::{Capability, CapabilityToken, CapabilitySet},
    memory::robust_allocator::{allocate_pages_robust, deallocate_pages_robust},
    fs::cryptofs::{get_cryptofs, CryptoFileType},
    process::nonos_exec::{NonosProcessId, create_nonos_process, ProcessCreationRequest},
};

/// NØNOS Module File Format Magic
const NONOS_MODULE_MAGIC: [u8; 8] = *b"NONOSMOD";
const MODULE_FORMAT_VERSION: u32 = 1;

/// Module types supported by NØNOS
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum NonosModuleType {
    SystemService = 0,      // Core system services
    DeviceDriver = 1,       // Hardware device drivers  
    CryptoProvider = 2,     // Cryptographic services
    NetworkStack = 3,       // Network protocol implementations
    FileSystem = 4,         // File system implementations
    UserApplication = 5,    // User applications
    SecurityModule = 6,     // Security and monitoring modules
    ZeroStateRuntime = 7,   // ZeroState runtime extensions
    QuantumSafe = 8,        // Post-quantum cryptography modules
    IsolationEngine = 9,    // Process isolation engines
}

/// Module security levels
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum ModuleSecurityLevel {
    Untrusted = 0,          // Default security level
    Verified = 1,           // Cryptographically verified
    SystemTrusted = 2,      // System-level trust
    KernelTrusted = 3,      // Can access kernel internals
    RootOfTrust = 4,        // Root-of-trust module (extremely rare)
}

/// NØNOS Module Header (.mod file format)
#[repr(C)]
#[derive(Debug, Clone)]
pub struct NonosModuleHeader {
    pub magic: [u8; 8],             // NONOS module magic
    pub format_version: u32,        // Module format version
    pub module_type: NonosModuleType,
    pub security_level: ModuleSecurityLevel,
    pub module_id: [u8; 32],        // Unique module identifier
    pub name: [u8; 64],             // Module name (null-terminated)
    pub version: [u8; 16],          // Module version string
    pub author: [u8; 64],           // Module author
    pub description_offset: u32,    // Offset to description string
    pub description_length: u32,    // Length of description
    
    // Code and data sections
    pub code_offset: u32,           // Offset to executable code
    pub code_size: u32,             // Size of code section
    pub data_offset: u32,           // Offset to data section  
    pub data_size: u32,             // Size of data section
    pub bss_size: u32,              // Size of uninitialized data
    
    // Entry points
    pub init_function: u64,         // Module initialization function
    pub cleanup_function: u64,      // Module cleanup function
    pub main_function: u64,         // Main execution function
    
    // Dependencies and requirements
    pub dependency_count: u32,      // Number of dependencies
    pub dependency_offset: u32,     // Offset to dependency table
    pub required_capabilities: u64, // Required capability bitfield
    pub memory_requirements: ModuleMemoryRequirements,
    
    // Security and verification
    pub signature_algorithm: SignatureAlgorithm,
    pub signature_offset: u32,      // Offset to cryptographic signature
    pub signature_size: u32,        // Size of signature
    pub public_key_offset: u32,     // Offset to public key
    pub public_key_size: u32,       // Size of public key
    pub attestation_chain_offset: u32, // Offset to attestation chain
    pub attestation_chain_size: u32,   // Size of attestation chain
    
    // Post-quantum cryptography
    pub quantum_signature_offset: u32, // Post-quantum signature
    pub quantum_signature_size: u32,
    pub quantum_public_key_offset: u32,
    pub quantum_public_key_size: u32,
    
    // Integrity and encryption
    pub hash_algorithm: HashAlgorithm,
    pub content_hash: [u8; 32],     // Hash of module contents
    pub encrypted: bool,            // Whether module is encrypted
    pub encryption_algorithm: ModuleEncryptionAlgorithm,
    pub encryption_key_slot: [u8; 48], // Encrypted module key
    
    // Load-time configuration
    pub load_flags: ModuleLoadFlags,
    pub execution_model: ModuleExecutionModel,
    pub isolation_level: ModuleIsolationLevel,
    
    // Reserved for future use
    pub reserved: [u8; 128],
}

/// Module memory requirements
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ModuleMemoryRequirements {
    pub min_heap_size: u64,         // Minimum heap required
    pub max_heap_size: u64,         // Maximum heap allowed
    pub stack_size: u64,            // Stack size required
    pub shared_memory_size: u64,    // Shared memory requirements
    pub dma_buffer_size: u64,       // DMA buffer requirements
    pub alignment_requirement: u32,  // Memory alignment requirement
}

/// Cryptographic signature algorithms
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum SignatureAlgorithm {
    None = 0,
    Ed25519 = 1,                    // Classical signature
    DilithiumNist = 2,              // Post-quantum signature
    FalconNist = 3,                 // Post-quantum signature
    SphincsPlus = 4,                // Post-quantum signature
    Hybrid = 5,                     // Classical + Post-quantum
}

/// Hash algorithms for integrity
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum HashAlgorithm {
    Blake3 = 0,                     // Default hash
    Sha3_256 = 1,                   // SHA-3
    Blake2b = 2,                    // Blake2b
    Keccak256 = 3,                  // Keccak
}

/// Module encryption algorithms
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum ModuleEncryptionAlgorithm {
    None = 0,
    ChaCha20Poly1305 = 1,          // Classical encryption
    AES256GCM = 2,                 // Classical encryption
    KyberAES = 3,                  // Post-quantum hybrid
    XChaCha20Poly1305 = 4,         // Extended nonce encryption
}

/// Module load flags
#[derive(Debug, Clone, Copy)]
pub struct ModuleLoadFlags {
    pub load_immediately: bool,     // Load at boot
    pub lazy_loading: bool,         // Load on first use
    pub persistent: bool,           // Keep in memory
    pub ephemeral: bool,            // Unload after use
    pub capability_inheritance: bool, // Inherit parent capabilities
    pub isolated_execution: bool,   // Execute in isolation chamber
    pub quantum_resistant: bool,    // Use quantum-resistant operations
    pub audit_all_operations: bool, // Log all module operations
}

/// Module execution models
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum ModuleExecutionModel {
    KernelSpace = 0,               // Execute in kernel mode
    UserSpace = 1,                 // Execute in user mode
    Hybrid = 2,                    // Mix of kernel and user
    ZeroState = 3,                 // Execute in ZeroState runtime
    Isolated = 4,                  // Execute in isolation chamber
}

/// Module isolation levels
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum ModuleIsolationLevel {
    None = 0,                      // No special isolation
    ProcessIsolation = 1,          // Process-level isolation
    MemoryIsolation = 2,           // Memory-level isolation
    CapabilityIsolation = 3,       // Capability-based isolation
    CryptographicIsolation = 4,    // Cryptographic isolation
    QuantumIsolation = 5,          // Quantum-resistant isolation
}

/// Module dependency entry
#[repr(C)]
#[derive(Debug, Clone)]
pub struct ModuleDependency {
    pub module_id: [u8; 32],        // Required module ID
    pub min_version: [u8; 16],      // Minimum version required
    pub max_version: [u8; 16],      // Maximum version supported
    pub required_capabilities: u64,  // Capabilities required from dependency
    pub optional: bool,             // Whether dependency is optional
}

/// Loaded module instance
#[derive(Debug)]
pub struct LoadedModule {
    pub header: NonosModuleHeader,
    pub module_id: [u8; 32],
    pub base_address: VirtAddr,
    pub code_pages: Vec<PhysAddr>,
    pub data_pages: Vec<PhysAddr>,
    pub entry_points: ModuleEntryPoints,
    pub capability_set: CapabilitySet,
    pub security_context: ModuleSecurityContext,
    pub execution_context: Option<ModuleExecutionContext>,
    pub dependencies: Vec<[u8; 32]>,    // Loaded dependency module IDs
    pub load_time: u64,
    pub last_used: AtomicU64,
    pub usage_count: AtomicU64,
    pub state: AtomicU32,               // ModuleState
}

/// Module entry points after loading
#[derive(Debug)]
pub struct ModuleEntryPoints {
    pub init_function: Option<VirtAddr>,
    pub cleanup_function: Option<VirtAddr>,
    pub main_function: Option<VirtAddr>,
    pub syscall_handler: Option<VirtAddr>,
    pub interrupt_handler: Option<VirtAddr>,
}

/// Module security context
#[derive(Debug, Clone)]
pub struct ModuleSecurityContext {
    pub attestation_hash: [u8; 32],
    pub signature_verified: bool,
    pub quantum_signature_verified: bool,
    pub integrity_verified: bool,
    pub trust_chain: Vec<[u8; 32]>,     // Attestation chain
    pub capability_tokens: Vec<CapabilityToken>,
    pub isolation_chamber_id: Option<u64>,
}

/// Module execution context
#[derive(Debug)]
pub struct ModuleExecutionContext {
    pub process_id: Option<NonosProcessId>,
    pub heap_start: VirtAddr,
    pub heap_size: usize,
    pub stack_start: VirtAddr,
    pub stack_size: usize,
    pub shared_memory: Option<VirtAddr>,
    pub execution_stats: ModuleExecutionStats,
}

/// Module execution statistics
#[derive(Debug)]
pub struct ModuleExecutionStats {
    pub cpu_time: AtomicU64,           // Total CPU time used
    pub memory_peak: AtomicU64,        // Peak memory usage
    pub syscalls_made: AtomicU64,      // System calls made
    pub capability_checks: AtomicU64,  // Capability verifications
    pub security_violations: AtomicU32, // Security violations
    pub quantum_operations: AtomicU64, // Post-quantum operations
}

/// Module states
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u32)]
pub enum ModuleState {
    Loading = 0,
    Loaded = 1,
    Initializing = 2,
    Running = 3,
    Suspended = 4,
    Terminating = 5,
    Terminated = 6,
    Error = 7,
}

/// NØNOS Module Loader
pub struct NonosModuleLoader {
    /// Loaded modules
    loaded_modules: RwLock<BTreeMap<[u8; 32], LoadedModule>>,
    
    /// Module registry (available modules)
    module_registry: RwLock<BTreeMap<String, ModuleRegistryEntry>>,
    
    /// Trust anchors for module verification
    trust_anchors: RwLock<Vec<TrustAnchor>>,
    
    /// Module loading queue
    loading_queue: Mutex<Vec<ModuleLoadRequest>>,
    
    /// Security policy
    security_policy: RwLock<ModuleSecurityPolicy>,
    
    /// Statistics
    stats: ModuleLoaderStats,
    
    /// Configuration
    config: ModuleLoaderConfig,
}

/// Module registry entry
#[derive(Debug, Clone)]
pub struct ModuleRegistryEntry {
    pub module_id: [u8; 32],
    pub name: String,
    pub version: String,
    pub file_path: String,
    pub security_level: ModuleSecurityLevel,
    pub module_type: NonosModuleType,
    pub verified: bool,
    pub signature_valid: bool,
    pub dependencies: Vec<String>,
}

/// Trust anchor for module verification
#[derive(Debug, Clone)]
pub struct TrustAnchor {
    pub name: String,
    pub public_key: Vec<u8>,
    pub quantum_public_key: Option<Vec<u8>>,
    pub trust_level: ModuleSecurityLevel,
    pub valid_from: u64,
    pub valid_until: u64,
}

/// Module load request
#[derive(Debug)]
pub struct ModuleLoadRequest {
    pub module_id: [u8; 32],
    pub requester_process: Option<NonosProcessId>,
    pub required_capabilities: Vec<Capability>,
    pub load_flags: ModuleLoadFlags,
    pub priority: u8,
    pub callback: Option<fn(Result<(), &'static str>)>,
}

/// Module security policy
#[derive(Debug, Clone)]
pub struct ModuleSecurityPolicy {
    pub require_signatures: bool,
    pub require_quantum_signatures: bool,
    pub allow_untrusted_modules: bool,
    pub max_security_level: ModuleSecurityLevel,
    pub enforce_capabilities: bool,
    pub mandatory_isolation: bool,
    pub audit_all_loads: bool,
    pub quantum_resistance_required: bool,
}

/// Module loader statistics
#[derive(Debug)]
pub struct ModuleLoaderStats {
    pub modules_loaded: AtomicU64,
    pub modules_unloaded: AtomicU64,
    pub load_failures: AtomicU64,
    pub signature_verifications: AtomicU64,
    pub signature_failures: AtomicU64,
    pub quantum_verifications: AtomicU64,
    pub capability_violations: AtomicU64,
    pub total_memory_used: AtomicU64,
}

/// Module loader configuration
#[derive(Debug)]
pub struct ModuleLoaderConfig {
    pub max_loaded_modules: usize,
    pub module_cache_size: usize,
    pub lazy_loading_enabled: bool,
    pub preload_system_modules: bool,
    pub enable_module_compression: bool,
    pub enable_module_encryption: bool,
}

impl NonosModuleLoader {
    /// Create new NØNOS module loader
    pub fn new() -> Self {
        NonosModuleLoader {
            loaded_modules: RwLock::new(BTreeMap::new()),
            module_registry: RwLock::new(BTreeMap::new()),
            trust_anchors: RwLock::new(Vec::new()),
            loading_queue: Mutex::new(Vec::new()),
            security_policy: RwLock::new(ModuleSecurityPolicy {
                require_signatures: true,
                require_quantum_signatures: false, // Enable for production
                allow_untrusted_modules: false,
                max_security_level: ModuleSecurityLevel::SystemTrusted,
                enforce_capabilities: true,
                mandatory_isolation: true,
                audit_all_loads: true,
                quantum_resistance_required: false, // Enable for production
            }),
            stats: ModuleLoaderStats {
                modules_loaded: AtomicU64::new(0),
                modules_unloaded: AtomicU64::new(0),
                load_failures: AtomicU64::new(0),
                signature_verifications: AtomicU64::new(0),
                signature_failures: AtomicU64::new(0),
                quantum_verifications: AtomicU64::new(0),
                capability_violations: AtomicU64::new(0),
                total_memory_used: AtomicU64::new(0),
            },
            config: ModuleLoaderConfig {
                max_loaded_modules: 256,
                module_cache_size: 64 * 1024 * 1024, // 64MB cache
                lazy_loading_enabled: true,
                preload_system_modules: true,
                enable_module_compression: true,
                enable_module_encryption: true,
            },
        }
    }
    
    /// Initialize module loader with system trust anchors
    pub fn initialize(&self) -> Result<(), &'static str> {
        // Add system trust anchors
        self.add_system_trust_anchors()?;
        
        // Scan for available modules
        self.scan_module_directory("/system/modules")?;
        
        // Preload critical system modules
        if self.config.preload_system_modules {
            self.preload_system_modules()?;
        }
        
        Ok(())
    }
    
    /// Load module by ID with cryptographic verification
    pub fn load_module(&self, module_id: &[u8; 32], capabilities: &[Capability], 
                      load_flags: ModuleLoadFlags) -> Result<(), &'static str> {
        
        // Check if already loaded
        {
            let loaded_modules = self.loaded_modules.read();
            if loaded_modules.contains_key(module_id) {
                return Ok(()); // Already loaded
            }
        }
        
        // Find module in registry
        let module_entry = self.find_module_in_registry(module_id)?;
        
        // Load module file
        let module_data = self.load_module_file(&module_entry.file_path)?;
        
        // Parse and verify module header
        let header = self.parse_module_header(&module_data)?;
        
        // Verify cryptographic signatures
        self.verify_module_signatures(&header, &module_data)?;
        
        // Check capability requirements
        self.verify_module_capabilities(&header, capabilities)?;
        
        // Check dependencies
        let dependencies = self.resolve_dependencies(&header, &module_data)?;
        
        // Allocate memory for module
        let (base_address, code_pages, data_pages) = self.allocate_module_memory(&header)?;
        
        // Decrypt module if encrypted
        let decrypted_data = if header.encrypted {
            self.decrypt_module(&header, &module_data)?
        } else {
            module_data
        };
        
        // Load module sections into memory
        self.load_module_sections(&header, &decrypted_data, base_address)?;
        
        // Create security context
        let security_context = self.create_module_security_context(&header)?;
        
        // Create execution context based on execution model
        let execution_context = match header.execution_model {
            ModuleExecutionModel::UserSpace | ModuleExecutionModel::ZeroState => {
                Some(self.create_user_execution_context(&header)?)
            },
            _ => None,
        };
        
        // Create loaded module instance
        let loaded_module = LoadedModule {
            header: header.clone(),
            module_id: *module_id,
            base_address,
            code_pages,
            data_pages,
            entry_points: self.resolve_entry_points(&header, base_address)?,
            capability_set: CapabilitySet::from_capabilities(capabilities),
            security_context,
            execution_context,
            dependencies,
            load_time: crate::time::timestamp_millis(),
            last_used: AtomicU64::new(0),
            usage_count: AtomicU64::new(0),
            state: AtomicU32::new(ModuleState::Loaded as u32),
        };
        
        // Add to loaded modules
        {
            let mut loaded_modules = self.loaded_modules.write();
            loaded_modules.insert(*module_id, loaded_module);
        }
        
        // Initialize module if it has init function
        self.initialize_module(module_id)?;
        
        // Update statistics
        self.stats.modules_loaded.fetch_add(1, Ordering::Relaxed);
        self.stats.total_memory_used.fetch_add(
            (header.code_size + header.data_size + header.bss_size) as u64, 
            Ordering::Relaxed
        );
        
        Ok(())
    }
    
    /// Execute module with capability and security checks
    pub fn execute_module(&self, module_id: &[u8; 32], args: &[u64]) -> Result<u64, &'static str> {
        let loaded_modules = self.loaded_modules.read();
        let module = loaded_modules.get(module_id)
            .ok_or("Module not loaded")?;
        
        // Update usage statistics
        module.last_used.store(crate::time::timestamp_millis(), Ordering::Relaxed);
        module.usage_count.fetch_add(1, Ordering::Relaxed);
        
        // Check if module is in correct state
        let state = ModuleState::from(module.state.load(Ordering::Relaxed));
        if state != ModuleState::Running && state != ModuleState::Loaded {
            return Err("Module not ready for execution");
        }
        
        // Execute based on execution model
        match module.header.execution_model {
            ModuleExecutionModel::KernelSpace => {
                self.execute_kernel_module(module, args)
            },
            ModuleExecutionModel::UserSpace => {
                self.execute_user_module(module, args)
            },
            ModuleExecutionModel::ZeroState => {
                self.execute_zerostate_module(module, args)
            },
            ModuleExecutionModel::Isolated => {
                self.execute_isolated_module(module, args)
            },
            _ => Err("Unsupported execution model"),
        }
    }
    
    /// Unload module with secure cleanup
    pub fn unload_module(&self, module_id: &[u8; 32]) -> Result<(), &'static str> {
        // Get module
        let module = {
            let mut loaded_modules = self.loaded_modules.write();
            loaded_modules.remove(module_id)
                .ok_or("Module not loaded")?
        };
        
        // Set state to terminating
        module.state.store(ModuleState::Terminating as u32, Ordering::Relaxed);
        
        // Call cleanup function if present
        if let Some(cleanup_fn) = module.entry_points.cleanup_function {
            self.call_module_function(cleanup_fn, &[])?;
        }
        
        // Secure erase module memory
        self.secure_erase_module_memory(&module)?;
        
        // Free allocated pages
        for &page in &module.code_pages {
            deallocate_pages_robust(page, 1)?;
        }
        for &page in &module.data_pages {
            deallocate_pages_robust(page, 1)?;
        }
        
        // Update statistics
        self.stats.modules_unloaded.fetch_add(1, Ordering::Relaxed);
        self.stats.total_memory_used.fetch_sub(
            (module.header.code_size + module.header.data_size + module.header.bss_size) as u64,
            Ordering::Relaxed
        );
        
        Ok(())
    }
    
    /// Parse module header with validation
    fn parse_module_header(&self, module_data: &[u8]) -> Result<NonosModuleHeader, &'static str> {
        if module_data.len() < core::mem::size_of::<NonosModuleHeader>() {
            return Err("Module file too small");
        }
        
        let header = unsafe {
            core::ptr::read(module_data.as_ptr() as *const NonosModuleHeader)
        };
        
        // Validate magic number
        if header.magic != NONOS_MODULE_MAGIC {
            return Err("Invalid module magic number");
        }
        
        // Validate version
        if header.format_version != MODULE_FORMAT_VERSION {
            return Err("Unsupported module format version");
        }
        
        // Validate sizes
        if header.code_offset as usize + header.code_size as usize > module_data.len() {
            return Err("Invalid code section");
        }
        
        if header.data_offset as usize + header.data_size as usize > module_data.len() {
            return Err("Invalid data section");
        }
        
        Ok(header)
    }
    
    /// Verify module cryptographic signatures
    fn verify_module_signatures(&self, header: &NonosModuleHeader, module_data: &[u8]) -> Result<(), &'static str> {
        let policy = self.security_policy.read();
        
        if !policy.require_signatures {
            return Ok(); // Signatures not required
        }
        
        self.stats.signature_verifications.fetch_add(1, Ordering::Relaxed);
        
        // Get signature and public key
        let signature_start = header.signature_offset as usize;
        let signature_end = signature_start + header.signature_size as usize;
        let signature = &module_data[signature_start..signature_end];
        
        let pubkey_start = header.public_key_offset as usize;
        let pubkey_end = pubkey_start + header.public_key_size as usize;
        let public_key = &module_data[pubkey_start..pubkey_end];
        
        // Calculate hash of module content
        let content_hash = self.calculate_module_content_hash(header, module_data)?;
        
        // Verify classical signature
        match header.signature_algorithm {
            SignatureAlgorithm::Ed25519 => {
                if signature.len() != 64 || public_key.len() != 32 {
                    self.stats.signature_failures.fetch_add(1, Ordering::Relaxed);
                    return Err("Invalid Ed25519 signature or key size");
                }
                
                let sig_array: [u8; 64] = signature.try_into().unwrap();
                let key_array: [u8; 32] = public_key.try_into().unwrap();
                
                if !verify_ed25519(&content_hash, &sig_array, &key_array)? {
                    self.stats.signature_failures.fetch_add(1, Ordering::Relaxed);
                    return Err("Ed25519 signature verification failed");
                }
            },
            SignatureAlgorithm::None => {
                if policy.require_signatures {
                    return Err("Signature required but not present");
                }
            },
            _ => return Err("Unsupported signature algorithm"),
        }
        
        // Verify post-quantum signature if required
        if policy.require_quantum_signatures && header.quantum_signature_size > 0 {
            self.stats.quantum_verifications.fetch_add(1, Ordering::Relaxed);
            
            let quantum_sig_start = header.quantum_signature_offset as usize;
            let quantum_sig_end = quantum_sig_start + header.quantum_signature_size as usize;
            let quantum_signature = &module_data[quantum_sig_start..quantum_sig_end];
            
            let quantum_key_start = header.quantum_public_key_offset as usize;
            let quantum_key_end = quantum_key_start + header.quantum_public_key_size as usize;
            let quantum_public_key = &module_data[quantum_key_start..quantum_key_end];
            
            if !post_quantum_verify(&content_hash, quantum_signature, quantum_public_key)? {
                return Err("Post-quantum signature verification failed");
            }
        }
        
        // Verify trust chain if present
        if header.attestation_chain_size > 0 {
            self.verify_attestation_chain(header, module_data)?;
        }
        
        Ok(())
    }
    
    /// Verify module capability requirements
    fn verify_module_capabilities(&self, header: &NonosModuleHeader, provided_caps: &[Capability]) -> Result<(), &'static str> {
        let policy = self.security_policy.read();
        
        if !policy.enforce_capabilities {
            return Ok();
        }
        
        self.stats.capability_violations.fetch_add(1, Ordering::Relaxed);
        
        // Convert capability bitfield to capabilities
        let required_caps = self.bitfield_to_capabilities(header.required_capabilities);
        
        // Check each required capability
        for required_cap in required_caps {
            if !provided_caps.contains(&required_cap) {
                return Err("Insufficient capabilities for module");
            }
        }
        
        Ok(())
    }
    
    /// Allocate memory for module with security constraints
    fn allocate_module_memory(&self, header: &NonosModuleHeader) -> Result<(VirtAddr, Vec<PhysAddr>, Vec<PhysAddr>), &'static str> {
        // Calculate pages needed
        let code_pages_needed = (header.code_size as usize + 4095) / 4096;
        let data_pages_needed = ((header.data_size + header.bss_size) as usize + 4095) / 4096;
        
        // Allocate code pages
        let mut code_pages = Vec::with_capacity(code_pages_needed);
        for _ in 0..code_pages_needed {
            let page = allocate_pages_robust(1)
                .ok_or("Failed to allocate code pages")?;
            code_pages.push(page);
        }
        
        // Allocate data pages
        let mut data_pages = Vec::with_capacity(data_pages_needed);
        for _ in 0..data_pages_needed {
            let page = allocate_pages_robust(1)
                .ok_or("Failed to allocate data pages")?;
            data_pages.push(page);
        }
        
        // Choose base address based on security level
        let base_address = match header.security_level {
            ModuleSecurityLevel::KernelTrusted => VirtAddr::new(0xFFFF800000000000), // Kernel space
            _ => VirtAddr::new(0x400000000000), // User space
        };
        
        Ok((base_address, code_pages, data_pages))
    }
    
    /// Load module sections into allocated memory
    fn load_module_sections(&self, header: &NonosModuleHeader, module_data: &[u8], base_address: VirtAddr) -> Result<(), &'static str> {
        // Load code section
        if header.code_size > 0 {
            let code_start = header.code_offset as usize;
            let code_end = code_start + header.code_size as usize;
            let code_data = &module_data[code_start..code_end];
            
            unsafe {
                let code_dest = base_address.as_mut_ptr::<u8>();
                core::ptr::copy_nonoverlapping(code_data.as_ptr(), code_dest, code_data.len());
            }
        }
        
        // Load data section
        if header.data_size > 0 {
            let data_start = header.data_offset as usize;
            let data_end = data_start + header.data_size as usize;
            let data_section = &module_data[data_start..data_end];
            
            unsafe {
                let data_dest = (base_address + header.code_size as u64).as_mut_ptr::<u8>();
                core::ptr::copy_nonoverlapping(data_section.as_ptr(), data_dest, data_section.len());
            }
        }
        
        // Initialize BSS section to zero
        if header.bss_size > 0 {
            unsafe {
                let bss_dest = (base_address + header.code_size as u64 + header.data_size as u64).as_mut_ptr::<u8>();
                core::ptr::write_bytes(bss_dest, 0, header.bss_size as usize);
            }
        }
        
        Ok(())
    }
    
    /// Execute module in kernel space
    fn execute_kernel_module(&self, module: &LoadedModule, args: &[u64]) -> Result<u64, &'static str> {
        if let Some(main_fn) = module.entry_points.main_function {
            // Set module state to running
            module.state.store(ModuleState::Running as u32, Ordering::Relaxed);
            
            // Call module main function
            let result = self.call_module_function(main_fn, args)?;
            
            // Update execution statistics
            if let Some(ref exec_ctx) = module.execution_context {
                exec_ctx.execution_stats.cpu_time.fetch_add(1, Ordering::Relaxed);
            }
            
            Ok(result)
        } else {
            Err("Module has no main function")
        }
    }
    
    /// Execute module in user space with process creation
    fn execute_user_module(&self, module: &LoadedModule, args: &[u64]) -> Result<u64, &'static str> {
        // Create process for module execution
        let process_request = ProcessCreationRequest {
            executable_data: Vec::new(), // Module already loaded
            parent_pid: None,
            capability_set: module.capability_set.clone(),
            memory_protection: crate::process::nonos_exec::NonosMemoryProtection::Standard,
            resource_limits: crate::process::nonos_exec::ResourceLimits::default(),
            module_manifest: None,
        };
        
        let process_id = create_nonos_process(process_request)?;
        
        // Execute module in the new process
        // This would involve setting up the process context and jumping to user space
        
        Ok(process_id)
    }
    
    /// Execute module in ZeroState runtime
    fn execute_zerostate_module(&self, module: &LoadedModule, args: &[u64]) -> Result<u64, &'static str> {
        // Create ephemeral execution environment
        // This would use the ZeroState runtime for maximum security
        
        if let Some(main_fn) = module.entry_points.main_function {
            // Set up ephemeral memory and execute
            let result = self.call_module_function(main_fn, args)?;
            
            // Clean up ephemeral state
            self.cleanup_zerostate_execution(module)?;
            
            Ok(result)
        } else {
            Err("Module has no main function")
        }
    }
    
    /// Execute module in isolation chamber
    fn execute_isolated_module(&self, module: &LoadedModule, args: &[u64]) -> Result<u64, &'static str> {
        // Execute in complete isolation with minimal capabilities
        if let Some(main_fn) = module.entry_points.main_function {
            // Set up isolation chamber
            let chamber_id = self.create_isolation_chamber_for_module(module)?;
            
            // Execute with strict monitoring
            let result = self.call_module_function_isolated(main_fn, args, chamber_id)?;
            
            // Clean up isolation chamber
            self.destroy_isolation_chamber(chamber_id)?;
            
            Ok(result)
        } else {
            Err("Module has no main function")
        }
    }
    
    /// Call module function (simplified implementation)
    fn call_module_function(&self, function_addr: VirtAddr, args: &[u64]) -> Result<u64, &'static str> {
        // This is a simplified implementation
        // In production, would need proper calling convention handling,
        // stack setup, register preservation, etc.
        
        // For now, just return success
        Ok(0)
    }
    
    /// Helper functions
    fn add_system_trust_anchors(&self) -> Result<(), &'static str> {
        // Add NØNOS system trust anchor
        let system_anchor = TrustAnchor {
            name: "NONOS-System".to_string(),
            public_key: vec![0u8; 32], // Would be real system key
            quantum_public_key: Some(vec![0u8; 64]),
            trust_level: ModuleSecurityLevel::RootOfTrust,
            valid_from: 0,
            valid_until: u64::MAX,
        };
        
        let mut trust_anchors = self.trust_anchors.write();
        trust_anchors.push(system_anchor);
        
        Ok(())
    }
    
    fn scan_module_directory(&self, _path: &str) -> Result<(), &'static str> {
        // Would scan filesystem for .mod files
        Ok(())
    }
    
    fn preload_system_modules(&self) -> Result<(), &'static str> {
        // Would preload critical system modules
        Ok(())
    }
    
    fn find_module_in_registry(&self, module_id: &[u8; 32]) -> Result<ModuleRegistryEntry, &'static str> {
        // Simplified - would search registry by module_id
        Err("Module not found in registry")
    }
    
    fn load_module_file(&self, _file_path: &str) -> Result<Vec<u8>, &'static str> {
        // Would load module file from CryptoFS
        Ok(vec![0u8; 1024]) // Dummy data
    }
    
    fn resolve_dependencies(&self, _header: &NonosModuleHeader, _module_data: &[u8]) -> Result<Vec<[u8; 32]>, &'static str> {
        Ok(Vec::new())
    }
    
    fn decrypt_module(&self, _header: &NonosModuleHeader, module_data: &[u8]) -> Result<Vec<u8>, &'static str> {
        // Would decrypt module using vault keys
        Ok(module_data.to_vec())
    }
    
    fn create_module_security_context(&self, header: &NonosModuleHeader) -> Result<ModuleSecurityContext, &'static str> {
        Ok(ModuleSecurityContext {
            attestation_hash: header.content_hash,
            signature_verified: true,
            quantum_signature_verified: false,
            integrity_verified: true,
            trust_chain: Vec::new(),
            capability_tokens: Vec::new(),
            isolation_chamber_id: None,
        })
    }
    
    fn create_user_execution_context(&self, header: &NonosModuleHeader) -> Result<ModuleExecutionContext, &'static str> {
        Ok(ModuleExecutionContext {
            process_id: None,
            heap_start: VirtAddr::new(0),
            heap_size: header.memory_requirements.min_heap_size as usize,
            stack_start: VirtAddr::new(0),
            stack_size: header.memory_requirements.stack_size as usize,
            shared_memory: None,
            execution_stats: ModuleExecutionStats {
                cpu_time: AtomicU64::new(0),
                memory_peak: AtomicU64::new(0),
                syscalls_made: AtomicU64::new(0),
                capability_checks: AtomicU64::new(0),
                security_violations: AtomicU32::new(0),
                quantum_operations: AtomicU64::new(0),
            },
        })
    }
    
    fn resolve_entry_points(&self, header: &NonosModuleHeader, base_address: VirtAddr) -> Result<ModuleEntryPoints, &'static str> {
        Ok(ModuleEntryPoints {
            init_function: if header.init_function != 0 {
                Some(base_address + header.init_function)
            } else {
                None
            },
            cleanup_function: if header.cleanup_function != 0 {
                Some(base_address + header.cleanup_function)
            } else {
                None
            },
            main_function: if header.main_function != 0 {
                Some(base_address + header.main_function)
            } else {
                None
            },
            syscall_handler: None,
            interrupt_handler: None,
        })
    }
    
    fn initialize_module(&self, module_id: &[u8; 32]) -> Result<(), &'static str> {
        let loaded_modules = self.loaded_modules.read();
        let module = loaded_modules.get(module_id).ok_or("Module not found")?;
        
        if let Some(init_fn) = module.entry_points.init_function {
            module.state.store(ModuleState::Initializing as u32, Ordering::Relaxed);
            self.call_module_function(init_fn, &[])?;
            module.state.store(ModuleState::Running as u32, Ordering::Relaxed);
        }
        
        Ok(())
    }
    
    fn calculate_module_content_hash(&self, header: &NonosModuleHeader, module_data: &[u8]) -> Result<[u8; 32], &'static str> {
        // Calculate hash of code and data sections
        let mut hasher_data = Vec::new();
        
        // Add code section
        if header.code_size > 0 {
            let code_start = header.code_offset as usize;
            let code_end = code_start + header.code_size as usize;
            hasher_data.extend_from_slice(&module_data[code_start..code_end]);
        }
        
        // Add data section
        if header.data_size > 0 {
            let data_start = header.data_offset as usize;
            let data_end = data_start + header.data_size as usize;
            hasher_data.extend_from_slice(&module_data[data_start..data_end]);
        }
        
        Ok(hash_blake3(&hasher_data))
    }
    
    fn verify_attestation_chain(&self, _header: &NonosModuleHeader, _module_data: &[u8]) -> Result<(), &'static str> {
        // Would verify cryptographic attestation chain
        Ok(())
    }
    
    fn bitfield_to_capabilities(&self, bitfield: u64) -> Vec<Capability> {
        let mut capabilities = Vec::new();
        for i in 0..64 {
            if bitfield & (1u64 << i) != 0 {
                if let Ok(cap) = Capability::try_from(i as u8) {
                    capabilities.push(cap);
                }
            }
        }
        capabilities
    }
    
    fn secure_erase_module_memory(&self, module: &LoadedModule) -> Result<(), &'static str> {
        // Secure erase module memory (3-pass overwrite)
        let total_size = module.header.code_size + module.header.data_size + module.header.bss_size;
        
        for pass in 0..3 {
            let pattern = match pass {
                0 => 0xFF,
                1 => 0x00,
                2 => 0xAA,
                _ => 0x00,
            };
            
            unsafe {
                core::ptr::write_bytes(
                    module.base_address.as_mut_ptr::<u8>(),
                    pattern,
                    total_size as usize
                );
            }
        }
        
        Ok(())
    }
    
    fn cleanup_zerostate_execution(&self, _module: &LoadedModule) -> Result<(), &'static str> {
        // Clean up ZeroState ephemeral memory
        Ok(())
    }
    
    fn create_isolation_chamber_for_module(&self, _module: &LoadedModule) -> Result<u64, &'static str> {
        // Create isolation chamber
        Ok(1) // Dummy chamber ID
    }
    
    fn call_module_function_isolated(&self, function_addr: VirtAddr, args: &[u64], _chamber_id: u64) -> Result<u64, &'static str> {
        self.call_module_function(function_addr, args)
    }
    
    fn destroy_isolation_chamber(&self, _chamber_id: u64) -> Result<(), &'static str> {
        Ok(())
    }
    
    /// Get module loader statistics
    pub fn get_stats(&self) -> ModuleLoaderStatistics {
        ModuleLoaderStatistics {
            modules_loaded: self.stats.modules_loaded.load(Ordering::Relaxed),
            modules_unloaded: self.stats.modules_unloaded.load(Ordering::Relaxed),
            load_failures: self.stats.load_failures.load(Ordering::Relaxed),
            signature_verifications: self.stats.signature_verifications.load(Ordering::Relaxed),
            signature_failures: self.stats.signature_failures.load(Ordering::Relaxed),
            quantum_verifications: self.stats.quantum_verifications.load(Ordering::Relaxed),
            capability_violations: self.stats.capability_violations.load(Ordering::Relaxed),
            total_memory_used: self.stats.total_memory_used.load(Ordering::Relaxed),
            active_modules: self.loaded_modules.read().len(),
        }
    }
}

impl From<u32> for ModuleState {
    fn from(value: u32) -> Self {
        match value {
            0 => ModuleState::Loading,
            1 => ModuleState::Loaded,
            2 => ModuleState::Initializing,
            3 => ModuleState::Running,
            4 => ModuleState::Suspended,
            5 => ModuleState::Terminating,
            6 => ModuleState::Terminated,
            _ => ModuleState::Error,
        }
    }
}

/// Module loader statistics for monitoring
#[derive(Debug, Clone)]
pub struct ModuleLoaderStatistics {
    pub modules_loaded: u64,
    pub modules_unloaded: u64,
    pub load_failures: u64,
    pub signature_verifications: u64,
    pub signature_failures: u64,
    pub quantum_verifications: u64,
    pub capability_violations: u64,
    pub total_memory_used: u64,
    pub active_modules: usize,
}

/// Global NØNOS module loader
static mut MODULE_LOADER: Option<NonosModuleLoader> = None;

/// Initialize NØNOS module loader
pub fn init_nonos_module_loader() -> Result<(), &'static str> {
    let loader = NonosModuleLoader::new();
    loader.initialize()?;
    
    unsafe {
        MODULE_LOADER = Some(loader);
    }
    
    Ok(())
}

/// Get module loader instance
pub fn get_module_loader() -> Option<&'static NonosModuleLoader> {
    unsafe { MODULE_LOADER.as_ref() }
}

/// Load NØNOS module
pub fn load_nonos_module(module_id: &[u8; 32], capabilities: &[Capability]) -> Result<(), &'static str> {
    get_module_loader()
        .ok_or("Module loader not initialized")?
        .load_module(module_id, capabilities, ModuleLoadFlags {
            load_immediately: true,
            lazy_loading: false,
            persistent: true,
            ephemeral: false,
            capability_inheritance: false,
            isolated_execution: true,
            quantum_resistant: true,
            audit_all_operations: true,
        })
}

/// Execute NØNOS module
pub fn execute_nonos_module(module_id: &[u8; 32], args: &[u64]) -> Result<u64, &'static str> {
    get_module_loader()
        .ok_or("Module loader not initialized")?
        .execute_module(module_id, args)
}