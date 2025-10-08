pub mod nonos_capability;
pub mod nonos_advanced_security;
pub mod nonos_audit;
pub mod nonos_firmware_db;
pub mod nonos_module_db;
pub mod nonos_monitor;
pub mod nonos_random;
pub mod nonos_rootkit_scanner;
pub mod nonos_signature_scanner;
pub mod nonos_threat_intel;
pub mod nonos_trusted_hashes;
pub mod nonos_trusted_keys;
pub mod nonos_data_leak_detection;
pub mod nonos_dns_privacy;
pub mod nonos_privacy_violation;
pub mod nonos_incident_response;
pub mod nonos_zkids;
pub mod nonos_quantum_security_engine;

// Re-export for compatibility
pub use nonos_capability as capability;
pub use nonos_advanced_security as advanced_security;
pub use nonos_audit as audit;
pub use nonos_firmware_db as firmware_db;
pub use nonos_module_db as module_db;
pub use nonos_monitor as monitor;
pub use nonos_random as random;
pub use nonos_rootkit_scanner as rootkit_scanner;
pub use nonos_signature_scanner as signature_scanner;
pub use nonos_threat_intel as threat_intel;
pub use nonos_trusted_hashes as trusted_hashes;
pub use nonos_trusted_keys as trusted_keys;
pub use nonos_data_leak_detection as data_leak_detection;
pub use nonos_dns_privacy as dns_privacy;
pub use nonos_privacy_violation as privacy_violation;
pub use nonos_incident_response as incident_response;
pub use nonos_zkids as zkids;

/// Isolation module for process chambers
pub mod isolation {
    use alloc::vec::Vec;
    
    #[derive(Debug, Clone)]
    pub struct IsolationChamber {
        pub chamber_id: [u8; 32],
        pub process_id: u64,
        pub memory_regions: Vec<(u64, usize)>,
        pub capabilities: Vec<u32>,
    }
    
    pub fn create_chamber(process_id: u64, capabilities: &[u32]) -> Result<IsolationChamber, &'static str> {
        let mut chamber_id = [0u8; 32];
        chamber_id[..8].copy_from_slice(&process_id.to_le_bytes());
        
        Ok(IsolationChamber {
            chamber_id,
            process_id,
            memory_regions: Vec::new(),
            capabilities: capabilities.to_vec(),
        })
    }
}

pub use nonos_capability::*;
pub use nonos_advanced_security::*;
pub use nonos_audit::*;
pub use nonos_firmware_db::*;
pub use nonos_module_db::*;
pub use nonos_monitor::*;
pub use nonos_random::*;
pub use nonos_rootkit_scanner::*;
pub use nonos_signature_scanner::*;
pub use nonos_threat_intel::*;
pub use nonos_trusted_hashes::*;
pub use nonos_trusted_keys::*;
pub use nonos_data_leak_detection::*;
pub use nonos_dns_privacy::*;
pub use nonos_privacy_violation::*;
pub use nonos_incident_response::*;
pub use nonos_zkids::*;

/// Initialize capability enforcement engine
pub fn init_capability_engine() -> Result<(), &'static str> {
    // Initialize capability system
    nonos_capability::init_nonos_capabilities()?;
    
    // Initialize ZKIDS authentication system
    nonos_zkids::init_zkids()?;
    
    // Initialize security modules, ignoring errors for now
    let _ = nonos_signature_scanner::init();
    let _ = nonos_trusted_keys::init(); 
    let _ = nonos_trusted_hashes::init();
    let _ = nonos_firmware_db::init();
    let _ = nonos_random::init();
    let _ = nonos_rootkit_scanner::init();
    let _ = nonos_threat_intel::init();
    
    Ok(())
}

/// Initialize all security subsystems
pub fn init() {
    // Initialize security modules, ignoring errors for now
    let _ = nonos_signature_scanner::init();
    let _ = nonos_trusted_keys::init(); 
    let _ = nonos_trusted_hashes::init();
    let _ = nonos_firmware_db::init();
    let _ = nonos_random::init();
    let _ = nonos_rootkit_scanner::init();
    let _ = nonos_threat_intel::init();
}

/// Run security monitor daemon
pub fn run_security_monitor() {
    init_security_monitor().unwrap_or(());
}

/// Run periodic security checks
pub fn run_periodic_checks() {
    // Run rootkit scanner
    nonos_rootkit_scanner::scan_system();
    
    // Check for data leakage
    nonos_data_leak_detection::scan_memory();
    
    // Validate trusted hashes
    nonos_trusted_hashes::verify_integrity();
    
    // Monitor privacy violations
    nonos_privacy_violation::check_violations();
}

/// Initialize security subsystem
pub fn init_security_subsystem() -> Result<(), &'static str> {
    crate::log_info!("Initializing security subsystem");
    
    // Initialize capability engine
    init_capability_engine()?;
    
    // Initialize advanced security
    nonos_advanced_security::init();
    
    // Initialize rootkit scanner
    nonos_rootkit_scanner::init();
    
    crate::log_info!("Security subsystem initialized");
    Ok(())
}