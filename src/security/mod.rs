//! # NØNOS Security Subsystem

#![no_std]
extern crate alloc;

// --- Module Declarations ---
pub mod nonos_capability;
pub mod nonos_advanced_security;
pub mod nonos_audit;
pub mod nonos_firmware_db;
pub mod nonos_module_db;
pub mod nonos_monitor;
pub mod nonos_random;
pub mod nonos_rootkit_scanner;
// pub mod nonos_signature_scanner;
// pub mod nonos_threat_intel;
pub mod nonos_trusted_hashes;
pub mod nonos_trusted_keys;
pub mod nonos_data_leak_detection;
pub mod nonos_dns_privacy;
// pub mod nonos_privacy_violation;
// pub mod nonos_incident_response;
pub mod nonos_zkids;
pub mod nonos_quantum_security_engine;

// --- Re-Exports ---
pub use nonos_capability::*;
pub use nonos_advanced_security::*;
pub use nonos_audit as audit;
pub use nonos_audit::*;
pub use nonos_firmware_db::*;
pub use nonos_module_db::*;
pub use nonos_monitor::*;
pub use nonos_random::*;
pub use nonos_rootkit_scanner::*;
// pub use nonos_signature_scanner::*;
// pub use nonos_threat_intel::*;
pub use nonos_trusted_hashes::*;
pub use nonos_trusted_keys::*;
pub use nonos_data_leak_detection::*;
pub use nonos_dns_privacy::*;
// pub use nonos_privacy_violation::*;
// pub use nonos_incident_response::*;
pub use nonos_zkids::*;
pub use nonos_quantum_security_engine::*;

// --- Unified Initialization ---
pub fn init_all_security() -> Result<(), &'static str> {
    // Capability system
    nonos_capability::init_nonos_capabilities()?;
    // Advanced security subsystem
    nonos_advanced_security::init_advanced_security()?;
    // Audit framework
    nonos_audit::init()?;
    // Firmware and module trust DB
    nonos_firmware_db::init()?;
    nonos_module_db::init()?;
    // Monitor (daemon can be enabled separately)
    nonos_monitor::set_enabled(true);
    // Randomness subsystem
    nonos_random::init()?;
    // Rootkit & signature scanners
    nonos_rootkit_scanner::init()?;
    // nonos_signature_scanner::init()?; // TODO: module missing
    // Threat intelligence
    // nonos_threat_intel::init()?; // TODO: module missing
    // Trusted hashes and keys
    nonos_trusted_hashes::init()?;
    nonos_trusted_keys::init()?;
    // Data leak and privacy
    nonos_data_leak_detection::add_sensitive_pattern("password");
    nonos_data_leak_detection::add_sensitive_pattern("private_key");
    nonos_data_leak_detection::add_sensitive_pattern("ssn");
    nonos_dns_privacy::scan_dns_queries();
    // nonos_privacy_violation::check_violations(); // TODO: module missing
    // Incident response
    // nonos_incident_response::init()?; // TODO: module missing
    // ZKIDS identity system
    nonos_zkids::init_zkids()?;
    // Quantum security engine 
    let _ = nonos_quantum_security_engine::QuantumSecurityEngine::new();
    Ok(())
}

/// Run periodic security checks (via kernel timer/interrupt)
pub fn run_periodic_checks() {
    let _ = nonos_rootkit_scanner::scan_system();
    let _ = nonos_data_leak_detection::scan_memory();
    let _ = nonos_trusted_hashes::list_trusted_hashes();
    // let _ = nonos_privacy_violation::check_violations(); // TODO: module missing
    nonos_monitor::log_event(
        nonos_monitor::NonosSecurityEventType::IntegrityBreach,
        1,
        "Periodic security check completed".into(),
        None,
        None,
        None,
    );
}

/// Unified system-wide diagnostics and statistics
pub fn get_security_stats() -> SecurityStats {
    SecurityStats {
        advanced: nonos_advanced_security::security_manager().stats(),
        monitor: nonos_monitor::get_stats(),
        quantum: {
            nonos_quantum_security_engine::QuantumSecurityStats {
                key_count: 0,
                compliance_events: 0,
                qkd_count: 0,
            }
        },
        zkids: nonos_zkids::get_zkids_stats(),
    }
}

/// Unified statistics struct
#[derive(Debug)]
pub struct SecurityStats {
    pub advanced: nonos_advanced_security::SecurityStats,
    pub monitor: nonos_monitor::NonosMonitorStats,
    pub quantum: nonos_quantum_security_engine::QuantumSecurityStats,
    pub zkids: nonos_zkids::ZkidsStats,
}
