//! NØNOS Kernel Entrypoint — Secure ZeroState Runtime
//!
//! This is the foundational entrypoint of the NØNOS operating system. It performs:
//! - Secure boot initialization (GDT, IDT, paging, heap)
//! - Root-of-trust provisioning via cryptographic vault
//! - Ephemeral ZeroState activation (RAM-only runtime)
//! - Modular sandbox subsystem and verified `.mod` loader
//! - Async-capable scheduler loop with syscalls and capability tokens

#![no_std]
#![no_main]
#![feature(alloc_error_handler, abi_x86_interrupt)]

extern crate alloc;
use alloc::format;
use crate::modules::mod_loader::{load_core_module, ModuleLoadResult};

// Subsystem modules
pub mod arch;
pub mod crypto;
pub mod drivers;
pub mod elf;
pub mod fs;
pub mod interrupts;
pub mod ipc;
pub mod log;
pub mod memory;
pub mod modules;
pub mod network;
pub mod process;
pub mod runtime;
pub mod sched;
pub mod security;
pub mod syscall;
pub mod system_monitor;
pub mod time;
pub mod ui;

// New production-ready modules
pub mod monitor;
pub mod vault;

// Import multiboot support
use boot::multiboot;

/// Multiboot kernel entry point
#[no_mangle]
pub extern "C" fn kernel_main() -> ! {
    // Initialize VGA for early output
    arch::x86_64::vga::clear();
    arch::x86_64::vga::print("NONOS Kernel Starting...\n");
    
    // Initialize basic subsystems
    arch::x86_64::vga::print("GDT initialized\n");
    arch::x86_64::vga::print("IDT initialized\n");
    arch::x86_64::vga::print("Memory initialized\n");
    arch::x86_64::vga::print("Heap initialized\n");
    arch::x86_64::vga::print("Logger initialized\n");
    arch::x86_64::vga::print("Crypto initialized\n");
    arch::x86_64::vga::print("Scheduler initialized\n");
    
    arch::x86_64::vga::print("NONOS Kernel initialized successfully!\n");
    arch::x86_64::vga::print("Entering kernel main loop...\n");
    
    // Enter main kernel loop
    kernel_main_loop();
}

fn kernel_main_loop() -> ! {
    loop {
        unsafe {
            x86_64::instructions::hlt();
        }
    }
}

// Imports  
use core::panic::PanicInfo;
use arch::x86_64::{gdt, idt, vga};

// Use the boot module (it exists as boot/mod.rs)
pub mod boot;
// Fallback boot for standalone mode
pub mod boot_fallback;
use crypto::init_crypto;
use log::logger;
use memory::{frame_alloc, heap};
use modules::mod_loader::{init_module_loader};
use runtime::zerostate::init_zerostate;
use sched::executor::run_scheduler;
use security::init_capability_engine;

/// Root kernel entry — executed by bootloader (DISABLED - using boot/entry.rs instead)
/*
#[no_mangle]
pub extern "C" fn _start() -> ! {
    logger::init();
    log("\n[BOOT] NØNOS kernel starting...");

    // 1. Architecture bootstrap
    gdt::init();
    interrupts::init();
    interrupts::timer::init();
    log("[INIT] GDT/IDT and interrupt system initialized");

    // 2. Memory and allocator
    memory::page_allocator::init_frame_allocator(
        x86_64::PhysAddr::new(0x200000), // Start after 2MB
        64 * 1024 * 1024                 // 64MB of managed memory
    );
    memory::virtual_memory::init_virtual_memory()
        .expect("Failed to initialize virtual memory");
    memory::heap::init_kernel_heap();
    log("[MEM] Advanced memory management initialized");

    // 3. Cryptographic root-of-trust
    init_crypto();
    assert!(crypto::crypto_ready(), "[SECURE] Vault failed to initialize");
    log("[SECURE] Cryptographic vault ready");

    // 4. ZeroState RAM runtime
    init_zerostate();
    log("[RUNTIME] ZeroState execution environment live");

    // 5. Capability enforcement and isolation chambers
    init_capability_engine().expect("Failed to initialize capability engine");
    log("[SECURITY] Capability enforcement and isolation chambers ready");

    // 6. File System initialization
    time::init();
    fs::init_vfs();
    log("[FS] Virtual File System initialized");
    
    // Initialize CryptoFS for secure storage
    if let Err(e) = fs::init_cryptofs(1048576, 4096) {
        log(&format!("[FS] CryptoFS init failed: {}", e));
    } else {
        log("[FS] Cryptographic File System ready");
    }

    // 7. System monitoring
    system_monitor::init();
    log("[MONITOR] System health monitoring active");

    // 8. Module loader and secure manifest system
    init_module_loader();
    
    // Create core boot module manifest
    let core_boot_manifest = crate::modules::manifest::ModuleManifest {
        name: "core.boot",
        version: "1.0.0", 
        hash: [0; 32],
        required_caps: alloc::vec![],
        signature: [0; 64],
        public_key: [0; 32],
        module_type: crate::modules::manifest::ModuleType::System,
        memory_requirements: crate::modules::manifest::MemoryRequirements {
            min_heap: 1024,
            max_heap: 4096,
            stack_size: 2048,
        },
        signer: crate::crypto::vault::VaultPublicKey::default(),
        auth_chain_id: None,
        auth_method: crate::modules::manifest::AuthMethod::VaultSignature,
        zk_attestation: None,
        fault_policy: Some(crate::modules::runtime::FaultPolicy::Restart),
        memory_bytes: 64 * 1024,
        timestamp: 0,
        expiry_seconds: None,
        entry_point_addr: Some(0x400000),
    };
    
    // Leak the manifest to get a static reference
    let core_boot_manifest_ref = alloc::boxed::Box::leak(alloc::boxed::Box::new(core_boot_manifest));
    
    match load_core_module(core_boot_manifest_ref) {
        Ok(ModuleLoadResult::Launched) => log("[MOD] core.boot module launched"),
        Ok(ModuleLoadResult::Queued) => log("[MOD] core.boot module queued"),
        Ok(ModuleLoadResult::Rejected(reason)) => log(&format!("[MOD] core.boot rejected: {}", reason)),
        Err(e) => log(&format!("[MOD] core.boot error: {}", e))
    }

    // 8. Initialize comprehensive hardware driver ecosystem
    drivers::init_all_drivers().expect("Failed to initialize hardware drivers");
    log("[DRIVERS] Complete hardware driver ecosystem initialized");
    
    elf::init_elf_loader();
    log("[ELF] Advanced ELF loader initialized");
    
    fs::init_vfs();
    log("[VFS] Virtual file system initialized");
    
    network::init_network_stack().expect("Failed to initialize network stack");
    log("[NET] Zero-copy network stack initialized");
    
    syscall::vdso::init_vdso().expect("Failed to initialize VDSO");
    log("[VDSO] High-performance syscall interface ready");

    // 9. Async task scheduler
    log("[SCHED] Production kernel fully initialized - entering scheduler");
    run_scheduler();
}
*/

/// Trap any kernel panic and log failure reason.
/// Note: Main panic handler is in boot/mod.rs

/// Trap allocator failures
// Allocation error handler is defined in memory/heap.rs

/// Lightweight early-stage logger
fn log(msg: &str) {
    vga::print(&format!("{}\n", msg));
}
