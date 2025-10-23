#![no_std]

extern crate alloc;

use alloc::{string::String, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

/// Result of a rootkit scan
#[derive(Debug, Clone)]
pub struct NonosRootkitScanResult {
    pub timestamp: u64,
    pub suspicious_modules: Vec<String>,
    pub suspicious_files: Vec<String>,
    pub suspicious_syscalls: Vec<u32>,
    pub kernel_modifications: Vec<String>,
    pub alerts: Vec<String>,
    pub score: u8, // 0-100
}

static LAST_SCAN_RESULT: Mutex<Option<NonosRootkitScanResult>> = Mutex::new(None);
static SCAN_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Initialize the rootkit scanner (can load baseline hashes/policies)
pub fn init() -> Result<(), &'static str> {
    Ok(())
}

/// Perform a full rootkit scan (kernel, modules, syscalls, files)
pub fn scan_system() -> NonosRootkitScanResult {
    let suspicious_modules = scan_loaded_modules();
    let suspicious_files = scan_filesystem();
    let suspicious_syscalls = scan_syscall_table();
    let kernel_modifications = scan_kernel_integrity();

    let mut alerts = Vec::new();

    if !suspicious_modules.is_empty() {
        alerts.push(format!("Suspicious modules: {:?}", suspicious_modules));
    }
    if !suspicious_files.is_empty() {
        alerts.push(format!("Suspicious files: {:?}", suspicious_files));
    }
    if !suspicious_syscalls.is_empty() {
        alerts.push(format!("Syscall table anomalies: {:?}", suspicious_syscalls));
    }
    if !kernel_modifications.is_empty() {
        alerts.push(format!("Kernel memory modified: {:?}", kernel_modifications));
    }

    let score = if alerts.is_empty() { 0 }
        else { 20 * alerts.len() as u8 };

    let result = NonosRootkitScanResult {
        timestamp: crate::time::timestamp_millis(),
        suspicious_modules,
        suspicious_files,
        suspicious_syscalls,
        kernel_modifications,
        alerts,
        score,
    };

    {
        let mut lock = LAST_SCAN_RESULT.lock();
        *lock = Some(result.clone());
    }
    SCAN_COUNTER.fetch_add(1, Ordering::Relaxed);
    result
}

/// Retrieve last scan result
pub fn get_last_scan() -> Option<NonosRootkitScanResult> {
    LAST_SCAN_RESULT.lock().clone()
}

/// Scan loaded kernel/user modules for anomalies
fn scan_loaded_modules() -> Vec<String> {
    let mut out = Vec::new();
    let loaded = crate::security::nonos_module_db::get_loaded_modules();
    for m in loaded {
        // Check for suspicious names, missing hashes or untrusted modules
        let trusted = crate::security::nonos_module_db::is_trusted_module(&m);
        if !trusted || m.contains("rootkit") || m.contains("stealth") || m.contains("hide") {
            out.push(m);
        }
    }
    out
}

/// Scan filesystem for hidden or unauthorized files
fn scan_filesystem() -> Vec<String> {
    let mut out = Vec::new();
    // Example: integrate with VFS, scan /proc, /dev, /etc
    let files = crate::filesystem::list_hidden_files("/");
    if !files.is_empty() {
        for f in files {
            if f.contains("rootkit") || f.contains(".ko") || f.contains(".so") {
                out.push(f);
            }
        }
    }
    out
}

/// Scan syscall table for hooks or anomalies
fn scan_syscall_table() -> Vec<u32> {
    let mut out = Vec::new();
    // Example: compare syscall table hashes, check for unexpected handlers
    let anomalies = crate::arch::x86_64::syscall::detect_syscall_hooks();
    if anomalies {
        out.push(0xDEADBEEF);
    }
    out
}

/// Scan kernel memory and structures for unauthorized modification
fn scan_kernel_integrity() -> Vec<String> {
    let mut out = Vec::new();
    // Example: hash kernel .text/.data, check interrupt table, check page tables
    if !crate::memory::verify_kernel_data_integrity() {
        out.push("Kernel data section modified".into());
    }
    if !crate::arch::x86_64::idt::verify_idt_integrity() {
        out.push("Interrupt Descriptor Table modified".into());
    }
    if !crate::memory::verify_kernel_page_tables() {
        out.push("Kernel page tables tampered".into());
    }
    out
}
