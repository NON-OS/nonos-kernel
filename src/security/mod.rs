pub mod advanced_security;
pub mod audit;
pub mod capability;
pub mod data_leak_detection;
pub mod dns_privacy;
pub mod firmware_db;
pub mod incident_response;
pub mod module_db;
pub mod monitor;
pub mod nonos_capability;
pub mod privacy_violation;
pub mod random;
pub mod rootkit_scanner;
pub mod signature_scanner;
pub mod threat_intel;
pub mod trusted_hashes;
pub mod trusted_keys;

pub use advanced_security::*;
pub use audit::*;
pub use capability::*;
pub use data_leak_detection::*;
pub use dns_privacy::*;
pub use firmware_db::*;
pub use incident_response::*;
pub use module_db::*;
pub use monitor::*;
pub use nonos_capability::*;
pub use privacy_violation::*;
pub use random::*;
pub use rootkit_scanner::*;
pub use signature_scanner::*;
pub use threat_intel::*;
pub use trusted_hashes::*;
pub use trusted_keys::*;

/// Initialize capability enforcement engine
pub fn init_capability_engine() -> Result<(), &'static str> {
    // Initialize capability system
    capability::init_capability_system()?;
    nonos_capability::init_nonos_capabilities()?;

    // Initialize security modules, ignoring errors for now
    let _ = signature_scanner::init();
    let _ = trusted_keys::init();
    let _ = trusted_hashes::init();
    let _ = firmware_db::init();
    let _ = random::init();
    let _ = rootkit_scanner::init();
    let _ = threat_intel::init();

    Ok(())
}

/// Initialize all security subsystems
pub fn init() {
    // Initialize security modules, ignoring errors for now
    let _ = signature_scanner::init();
    let _ = trusted_keys::init();
    let _ = trusted_hashes::init();
    let _ = firmware_db::init();
    let _ = random::init();
    let _ = rootkit_scanner::init();
    let _ = threat_intel::init();
}

/// Run security monitor daemon
pub fn run_security_monitor() {
    init_security_monitor().unwrap_or(());
}

/// Run periodic security checks
pub fn run_periodic_checks() {
    // Run rootkit scanner
    rootkit_scanner::scan_system();

    // Check for data leakage
    data_leak_detection::scan_memory();

    // Validate trusted hashes
    trusted_hashes::verify_integrity();

    // Monitor privacy violations
    privacy_violation::check_violations();
}
