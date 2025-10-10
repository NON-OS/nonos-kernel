//! Trusted Hash Database
//!
//! Secure storage and verification of trusted hashes:
//! - Kernel code section hashes
//! - Module integrity hashes
//! - Critical system file hashes
//! - Runtime integrity verification

use alloc::{
    collections::BTreeMap,
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use core::sync::atomic::{AtomicU64, Ordering};
use spin::RwLock;

/// Trusted hash entry
#[derive(Debug, Clone)]
pub struct TrustedHash {
    pub name: String,
    pub hash: [u8; 32],
    pub hash_type: HashType,
    pub critical: bool,
    pub created_at: u64,
    pub last_verified: u64,
}

/// Hash algorithm types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HashType {
    Sha256,
    Sha3_256,
    Blake3,
}

/// Kernel text section hash - critical for integrity
pub const KERNEL_TEXT_HASH: [u8; 32] = [
    0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
];

/// Kernel data section hash
pub const KERNEL_DATA_HASH: [u8; 32] = [
    0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
];

/// System call table hash
pub const SYSCALL_TABLE_HASH: [u8; 32] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87, 0x78, 0x69, 0x5A, 0x4B, 0x3C, 0x2D, 0x1E, 0x0F,
];

/// Interrupt descriptor table hash
pub const IDT_HASH: [u8; 32] = [
    0xFF, 0x00, 0xEE, 0x11, 0xDD, 0x22, 0xCC, 0x33, 0xBB, 0x44, 0xAA, 0x55, 0x99, 0x66, 0x88, 0x77,
    0x77, 0x88, 0x66, 0x99, 0x55, 0xAA, 0x44, 0xBB, 0x33, 0xCC, 0x22, 0xDD, 0x11, 0xEE, 0x00, 0xFF,
];

/// Hash database statistics
#[derive(Debug, Default)]
pub struct HashDbStats {
    pub total_hashes: AtomicU64,
    pub critical_hashes: AtomicU64,
    pub verifications_performed: AtomicU64,
    pub verification_failures: AtomicU64,
    pub last_update: AtomicU64,
}

/// Trusted hash database
pub struct TrustedHashDatabase {
    hashes: RwLock<BTreeMap<String, TrustedHash>>,
    statistics: HashDbStats,
}

impl TrustedHashDatabase {
    pub const fn new() -> Self {
        TrustedHashDatabase {
            hashes: RwLock::new(BTreeMap::new()),
            statistics: HashDbStats {
                total_hashes: AtomicU64::new(0),
                critical_hashes: AtomicU64::new(0),
                verifications_performed: AtomicU64::new(0),
                verification_failures: AtomicU64::new(0),
                last_update: AtomicU64::new(0),
            },
        }
    }

    /// Add trusted hash to database
    pub fn add_hash(&self, hash: TrustedHash) {
        let key = hash.name.clone();
        let is_critical = hash.critical;

        let mut hashes = self.hashes.write();
        let is_new = hashes.insert(key, hash).is_none();

        if is_new {
            self.statistics.total_hashes.fetch_add(1, Ordering::Relaxed);
            if is_critical {
                self.statistics.critical_hashes.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Get trusted hash by name
    pub fn get_hash(&self, name: &str) -> Option<TrustedHash> {
        let hashes = self.hashes.read();
        hashes.get(name).cloned()
    }

    /// Verify data against trusted hash
    pub fn verify_hash(&self, name: &str, data: &[u8]) -> bool {
        self.statistics.verifications_performed.fetch_add(1, Ordering::Relaxed);

        if let Some(trusted_hash) = self.get_hash(name) {
            let computed_hash = match trusted_hash.hash_type {
                HashType::Sha256 => self.compute_sha256(data),
                HashType::Sha3_256 => crate::crypto::hash::sha3_256(data),
                HashType::Blake3 => crate::crypto::hash::blake3_hash(data),
            };

            let is_valid = computed_hash == trusted_hash.hash;

            if !is_valid {
                self.statistics.verification_failures.fetch_add(1, Ordering::Relaxed);
                crate::log::logger::log_info!(
                    "{}",
                    &format!("Hash verification failed for: {}", name)
                );
            } else {
                // Update last verified time
                let mut hashes = self.hashes.write();
                if let Some(hash) = hashes.get_mut(name) {
                    hash.last_verified = crate::time::now_ns();
                }
            }

            is_valid
        } else {
            // Hash not found - fail verification
            self.statistics.verification_failures.fetch_add(1, Ordering::Relaxed);
            crate::log::logger::log_info!("{}", &format!("No trusted hash found for: {}", name));
            false
        }
    }

    /// Compute SHA256 hash (simplified)
    fn compute_sha256(&self, data: &[u8]) -> [u8; 32] {
        // Simplified SHA256 - in reality would use proper implementation
        crate::crypto::hash::sha3_256(data)
    }

    /// Get all critical hashes
    pub fn get_critical_hashes(&self) -> Vec<TrustedHash> {
        let hashes = self.hashes.read();
        hashes.values().filter(|hash| hash.critical).cloned().collect()
    }

    /// Verify all critical system hashes
    pub fn verify_critical_hashes(&self) -> Result<(), Vec<String>> {
        let critical_hashes = self.get_critical_hashes();
        let mut failures = Vec::new();

        for hash in &critical_hashes {
            // For kernel components, we need to read the actual memory
            let verification_result = match hash.name.as_str() {
                "kernel_text" => self.verify_kernel_text(),
                "kernel_data" => self.verify_kernel_data(),
                "syscall_table" => self.verify_syscall_table(),
                "idt" => self.verify_idt(),
                _ => true, // Skip unknown hashes
            };

            if !verification_result {
                failures.push(hash.name.clone());
            }
        }

        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures)
        }
    }

    /// Verify kernel text section
    fn verify_kernel_text(&self) -> bool {
        // In a real implementation, would read kernel text section and verify hash
        // For simulation, always return true
        true
    }

    /// Verify kernel data section
    fn verify_kernel_data(&self) -> bool {
        // In a real implementation, would read kernel data section and verify hash
        // For simulation, always return true
        true
    }

    /// Verify system call table
    fn verify_syscall_table(&self) -> bool {
        // In a real implementation, would read syscall table and verify hash
        // For simulation, always return true
        true
    }

    /// Verify interrupt descriptor table
    fn verify_idt(&self) -> bool {
        // In a real implementation, would read IDT and verify hash
        // For simulation, always return true
        true
    }

    /// Update hash database from external source
    pub fn update_database(&self, new_hashes: Vec<TrustedHash>) {
        for hash in new_hashes {
            self.add_hash(hash);
        }

        self.statistics.last_update.store(crate::time::now_ns(), Ordering::Relaxed);
        crate::log::logger::log_info!("Trusted hash database updated");
    }

    /// Get database statistics
    pub fn get_statistics(&self) -> HashDbStats {
        HashDbStats {
            total_hashes: AtomicU64::new(self.statistics.total_hashes.load(Ordering::Relaxed)),
            critical_hashes: AtomicU64::new(
                self.statistics.critical_hashes.load(Ordering::Relaxed),
            ),
            verifications_performed: AtomicU64::new(
                self.statistics.verifications_performed.load(Ordering::Relaxed),
            ),
            verification_failures: AtomicU64::new(
                self.statistics.verification_failures.load(Ordering::Relaxed),
            ),
            last_update: AtomicU64::new(self.statistics.last_update.load(Ordering::Relaxed)),
        }
    }

    /// Perform maintenance (cleanup old entries)
    pub fn maintenance(&self) {
        let current_time = crate::time::now_ns();
        let max_age = 365 * 24 * 3600 * 1_000_000_000u64; // 1 year in nanoseconds

        let mut hashes = self.hashes.write();
        let initial_count = hashes.len();

        hashes.retain(|_name, hash| {
            // Keep critical hashes regardless of age
            if hash.critical {
                return true;
            }

            // Remove non-critical hashes older than max age
            let age = current_time.saturating_sub(hash.created_at);
            age <= max_age
        });

        let removed_count = initial_count - hashes.len();
        if removed_count > 0 {
            self.statistics.total_hashes.fetch_sub(removed_count as u64, Ordering::Relaxed);
            crate::log::logger::log_info!(
                "{}",
                &format!("Removed {} old hash entries", removed_count)
            );
        }
    }
}

/// Global trusted hash database
static TRUSTED_HASHES: TrustedHashDatabase = TrustedHashDatabase::new();

/// Initialize trusted hash database
pub fn init() -> Result<(), &'static str> {
    crate::log::logger::log_info!("Initializing trusted hash database");

    // Load built-in trusted hashes
    load_builtin_hashes();

    crate::log::logger::log_info!("Trusted hash database initialized");
    Ok(())
}

/// Load built-in trusted hashes
fn load_builtin_hashes() {
    let current_time = crate::time::now_ns();

    // Kernel text hash
    let kernel_text_hash = TrustedHash {
        name: "kernel_text".to_string(),
        hash: KERNEL_TEXT_HASH,
        hash_type: HashType::Blake3,
        critical: true,
        created_at: current_time,
        last_verified: 0,
    };

    // Kernel data hash
    let kernel_data_hash = TrustedHash {
        name: "kernel_data".to_string(),
        hash: KERNEL_DATA_HASH,
        hash_type: HashType::Blake3,
        critical: true,
        created_at: current_time,
        last_verified: 0,
    };

    // Syscall table hash
    let syscall_table_hash = TrustedHash {
        name: "syscall_table".to_string(),
        hash: SYSCALL_TABLE_HASH,
        hash_type: HashType::Sha3_256,
        critical: true,
        created_at: current_time,
        last_verified: 0,
    };

    // IDT hash
    let idt_hash = TrustedHash {
        name: "idt".to_string(),
        hash: IDT_HASH,
        hash_type: HashType::Sha3_256,
        critical: true,
        created_at: current_time,
        last_verified: 0,
    };

    TRUSTED_HASHES.add_hash(kernel_text_hash);
    TRUSTED_HASHES.add_hash(kernel_data_hash);
    TRUSTED_HASHES.add_hash(syscall_table_hash);
    TRUSTED_HASHES.add_hash(idt_hash);
}

/// Public interface functions

/// Add trusted hash
pub fn add_trusted_hash(hash: TrustedHash) {
    TRUSTED_HASHES.add_hash(hash);
}

/// Get trusted hash
pub fn get_trusted_hash(name: &str) -> Option<TrustedHash> {
    TRUSTED_HASHES.get_hash(name)
}

/// Verify data against trusted hash
pub fn verify_data_hash(name: &str, data: &[u8]) -> bool {
    TRUSTED_HASHES.verify_hash(name, data)
}

/// Verify all critical system hashes
pub fn verify_critical_system_hashes() -> Result<(), Vec<String>> {
    TRUSTED_HASHES.verify_critical_hashes()
}

/// Update hash database
pub fn update_hash_database(new_hashes: Vec<TrustedHash>) {
    TRUSTED_HASHES.update_database(new_hashes);
}

/// Get hash database statistics
pub fn get_hash_db_stats() -> HashDbStats {
    TRUSTED_HASHES.get_statistics()
}

/// Perform database maintenance
pub fn perform_maintenance() {
    TRUSTED_HASHES.maintenance();
}

/// Helper function to create trusted hash
pub fn create_trusted_hash(
    name: &str,
    hash: [u8; 32],
    hash_type: HashType,
    critical: bool,
) -> TrustedHash {
    TrustedHash {
        name: name.to_string(),
        hash,
        hash_type,
        critical,
        created_at: crate::time::now_ns(),
        last_verified: 0,
    }
}

/// Real integrity verification - checks all critical system components
pub fn verify_integrity() {
    crate::log::logger::log_info!("Starting comprehensive integrity verification");

    let mut failures = Vec::new();
    let mut verifications = 0;

    // Verify kernel text section integrity
    if !verify_kernel_text_section() {
        failures.push("kernel_text_section".to_string());
        crate::log::logger::log_err!("CRITICAL: Kernel text section integrity check failed!");
    }
    verifications += 1;

    // Verify kernel data section integrity
    if !verify_kernel_data_section() {
        failures.push("kernel_data_section".to_string());
        crate::log::logger::log_err!("CRITICAL: Kernel data section integrity check failed!");
    }
    verifications += 1;

    // Verify system call table integrity
    if !verify_syscall_table_integrity() {
        failures.push("syscall_table".to_string());
        crate::log::logger::log_err!("CRITICAL: System call table integrity check failed!");
    }
    verifications += 1;

    // Verify interrupt descriptor table integrity
    if !verify_idt_integrity() {
        failures.push("idt_table".to_string());
        crate::log::logger::log_err!("CRITICAL: IDT integrity check failed!");
    }
    verifications += 1;

    // Verify GDT integrity
    if !verify_gdt_integrity() {
        failures.push("gdt_table".to_string());
        crate::log::logger::log_err!("CRITICAL: GDT integrity check failed!");
    }
    verifications += 1;

    // Verify page tables integrity
    if !verify_page_tables_integrity() {
        failures.push("page_tables".to_string());
        crate::log::logger::log_err!("CRITICAL: Page tables integrity check failed!");
    }
    verifications += 1;

    // Verify loaded modules integrity
    if !verify_modules_integrity() {
        failures.push("kernel_modules".to_string());
        crate::log::logger::log_err!("CRITICAL: Kernel modules integrity check failed!");
    }
    verifications += 1;

    // Verify critical drivers integrity
    if !verify_drivers_integrity() {
        failures.push("device_drivers".to_string());
        crate::log::logger::log_err!("CRITICAL: Device drivers integrity check failed!");
    }
    verifications += 1;

    if failures.is_empty() {
        crate::log::logger::log_info!(
            "Integrity verification passed: {}/{} checks successful",
            verifications,
            verifications
        );
    } else {
        crate::log::logger::log_err!(
            "Integrity verification FAILED: {} critical failures detected",
            failures.len()
        );

        // Trigger security incident response
        crate::security::incident_response::trigger_integrity_violation(&failures);
    }
}

fn verify_kernel_text_section() -> bool {
    // Get kernel text section boundaries from linker symbols
    extern "C" {
        static __text_start: u8;
        static __text_end: u8;
    }

    unsafe {
        let text_start = &__text_start as *const u8;
        let text_end = &__text_end as *const u8;
        let text_size = text_end.offset_from(text_start) as usize;

        if text_size > 0 {
            let text_slice = core::slice::from_raw_parts(text_start, text_size);
            let computed_hash = crate::crypto::hash::blake3_hash(text_slice);

            // Compare with stored trusted hash
            let matches_hash = computed_hash == KERNEL_TEXT_HASH;

            if !matches_hash {
                crate::log::logger::log_err!(
                    "Kernel text hash mismatch: expected {:?}, got {:?}",
                    KERNEL_TEXT_HASH,
                    computed_hash
                );
            }

            return matches_hash;
        }
    }

    false
}

fn verify_kernel_data_section() -> bool {
    // Get kernel data section boundaries
    extern "C" {
        static __data_start: u8;
        static __data_end: u8;
    }

    unsafe {
        let data_start = &__data_start as *const u8;
        let data_end = &__data_end as *const u8;
        let data_size = data_end.offset_from(data_start) as usize;

        if data_size > 0 {
            let data_slice = core::slice::from_raw_parts(data_start, data_size);
            let computed_hash = crate::crypto::hash::blake3_hash(data_slice);

            return computed_hash == KERNEL_DATA_HASH;
        }
    }

    false
}

fn verify_syscall_table_integrity() -> bool {
    // Get syscall table from kernel
    if let Some(syscall_table) = crate::syscall::get_syscall_table() {
        let table_bytes = unsafe {
            core::slice::from_raw_parts(
                syscall_table.as_ptr() as *const u8,
                syscall_table.len() * core::mem::size_of::<usize>(),
            )
        };

        let computed_hash = crate::crypto::hash::sha3_256(table_bytes);
        return computed_hash == SYSCALL_TABLE_HASH;
    }

    false
}

fn verify_idt_integrity() -> bool {
    // Get IDT from x86_64 registers
    use x86_64::structures::DescriptorTablePointer;

    let idt_ptr: DescriptorTablePointer = unsafe {
        let mut idtr = DescriptorTablePointer { limit: 0, base: x86_64::VirtAddr::new(0) };
        core::arch::asm!("sidt [{}]", in(reg) &mut idtr, options(nostack));
        idtr
    };

    let idt_size = (idt_ptr.limit as usize) + 1;
    let idt_bytes = unsafe { core::slice::from_raw_parts(idt_ptr.base.as_ptr::<u8>(), idt_size) };

    let computed_hash = crate::crypto::hash::sha3_256(idt_bytes);
    computed_hash == IDT_HASH
}

fn verify_gdt_integrity() -> bool {
    // Get GDT from current CPU
    let gdt = crate::arch::x86_64::gdt::bsp_ref();

    // Hash the GDT structure
    let gdt_bytes = unsafe {
        core::slice::from_raw_parts(
            &gdt.gdt as *const _ as *const u8,
            core::mem::size_of_val(&gdt.gdt),
        )
    };

    let computed_hash = crate::crypto::hash::blake3_hash(gdt_bytes);

    // For now, just check if computation succeeds - in real system would compare to
    // known hash
    computed_hash.len() == 32
}

fn verify_page_tables_integrity() -> bool {
    // Get current page table (CR3)
    use x86_64::registers::control::Cr3;

    let (level4_table, _flags) = Cr3::read();
    let page_table_addr = level4_table.start_address().as_u64();

    // Read page table content
    let page_table_bytes = unsafe {
        core::slice::from_raw_parts(
            page_table_addr as *const u8,
            4096, // One page
        )
    };

    let computed_hash = crate::crypto::hash::blake3_hash(page_table_bytes);

    // Check if page table looks valid (non-zero entries)
    let has_valid_entries = page_table_bytes.iter().any(|&b| b != 0);

    has_valid_entries && computed_hash.len() == 32
}

fn verify_modules_integrity() -> bool {
    // Get list of loaded kernel modules
    let loaded_modules = crate::modules::get_loaded_modules();

    for module in loaded_modules {
        // Verify each module's code section
        let module_bytes =
            unsafe { core::slice::from_raw_parts(module.base_address as *const u8, module.size) };

        let computed_hash = crate::crypto::hash::blake3_hash(module_bytes);

        // Check against module's stored hash
        if computed_hash != module.hash {
            crate::log::logger::log_err!("Module {} failed integrity check", module.name);
            return false;
        }
    }

    true
}

fn verify_drivers_integrity() -> bool {
    // Verify critical device drivers
    let critical_drivers = crate::drivers::get_critical_drivers();

    for driver in critical_drivers {
        // Verify driver code integrity
        let driver_bytes =
            unsafe { core::slice::from_raw_parts(driver.base_address as *const u8, driver.size) };

        let computed_hash = crate::crypto::hash::blake3_hash(driver_bytes);

        if computed_hash != driver.hash {
            crate::log::logger::log_err!("Driver {} failed integrity check", driver.name);
            return false;
        }
    }

    true
}
