//! NØNOS Kernel Entrypoint — Secure ZeroState Runtime
#![no_std]
#![no_main]
#![feature(alloc_error_handler, abi_x86_interrupt)]

#[macro_use]
extern crate alloc;

pub use alloc::format;

pub mod arch;
pub mod boot;
pub mod capabilities;
pub mod crypto;
pub mod drivers;
pub mod elf;
pub mod filesystem;
pub mod fs;
pub mod interrupts;
pub mod ipc;
pub mod log;
pub mod manifest;
pub mod memory;
pub mod modules;
pub mod network;
pub mod process;
pub mod runtime;
pub mod sched;
pub mod security;
pub mod storage;
pub mod syscall;
pub mod system_monitor;
pub mod time;
pub mod ui;
pub mod vault;
pub mod zk_engine;
pub mod gfx;
pub mod text;

pub mod monitor {
    pub use crate::system_monitor::*;
    pub fn update_syscall_stats(syscall_num: u64, result: u64) {
        if result != 0 {
            crate::log::logger::log_info!(
                "Syscall {} completed with result {}",
                syscall_num,
                result
            );
        }
    }
}

//use core::panic::PanicInfo;
use arch::x86_64::{gdt, idt};
use sched::run_scheduler;

extern "C" {
    fn _arch_start() -> !;
}

// NOTE: The real entry on UEFI is in boot/entry.rs (handoff from bootloader).
// `kernel_main` remains for multiboot/legacy bring-up and tests.
#[no_mangle]
pub extern "C" fn kernel_main() -> ! {
    // Early logging via our logger (serial-backed). No VGA touches.
    log::logger::init();
    log_info("[BOOT] NONOS Kernel Starting (legacy entry)...");
    unsafe { kernel_init() }
}

// fn kernel_main_loop() -> ! {
//     loop {
//         unsafe { x86_64::instructions::hlt(); }
//     }
// }

/// Root kernel initialization sequence (shared by UEFI + legacy)
pub unsafe fn kernel_init() -> ! {
    log::logger::init();
    log_info("\n[BOOT] NØNOS kernel starting...");

    // 1) Platform detect + features
    let platform = arch::x86_64::multiboot::detect_platform();
    log_info(&format!("[PLATFORM] Detected platform: {:?}", platform));
    arch::x86_64::multiboot::init_platform_features(platform)
        .expect("Failed to initialize platform features");

    // 2) Arch bootstrap
    gdt::init();
    interrupts::init();
    interrupts::timer::init();
    log_info("[INIT] GDT/IDT and interrupt system initialized");

    // 3) Memory + allocator
    memory::page_allocator::init_frame_allocator(
        x86_64::PhysAddr::new(0x200000),
        64 * 1024 * 1024,
    );
    memory::virtual_memory::init_virtual_memory()
        .expect("Failed to initialize virtual memory");
    memory::heap::init_kernel_heap();
    log_info("[MEM] Advanced memory management initialized");

    // 4) Crypto ROT + ZK
    crypto::init_crypto();
    assert!(crypto::crypto_ready(), "[SECURE] Vault failed to initialize");
    log_info("[SECURE] Cryptographic vault ready");

    zk_engine::init_zk_engine().expect("Failed to initialize ZK engine");
    log_info("[ZK] Zero-knowledge proof engine and attestation system ready");

    // 5) ZeroState runtime
    runtime::zerostate::init_zerostate();
    log_info("[RUNTIME] ZeroState execution environment live");

    // 6) Capability enforcement
    security::init_capability_engine().expect("Failed to initialize capability engine");
    log_info("[SECURITY] Capability enforcement and isolation chambers ready");

    // 7) FS
    time::init();
    fs::init_vfs();
    log_info("[FS] Virtual File System initialized");

    if let Err(e) = fs::cryptofs::init_cryptofs(1_048_576, 4096) {
        log_warn(&format!("[FS] CryptoFS init failed: {}", e));
    } else {
        log_info("[FS] CryptoFS initialized");
    }

    // 8) Monitoring
    system_monitor::init();
    log_info("[MONITOR] System monitoring initialized");

    // 9) Modules
    modules::mod_loader::init_module_loader();

    // 10) Drivers + loaders + net + VDSO
    drivers::init_all_drivers().expect("Failed to initialize hardware drivers");
    log_info("[DRIVERS] Complete hardware driver ecosystem initialized");

    elf::init_elf_loader();
    log_info("[ELF] Advanced ELF loader initialized");

    fs::init_vfs();
    log_info("[VFS] Virtual file system initialized");

    network::init_network_stack().expect("Failed to initialize network stack");
    log_info("[NET] Zero-copy network stack initialized");

    syscall::vdso::init_vdso().expect("Failed to initialize VDSO");
    log_info("[VDSO] High-performance syscall interface ready");

    // 11) Scheduler
    log_info("[SCHED] Production kernel fully initialized - entering scheduler");
    run_scheduler();
}

// --- tiny helpers over logger to keep call-sites short ---
#[inline] fn log_info(msg: &str) { crate::log::logger::log_info!("{}", msg); }
#[inline] fn log_warn(msg: &str) { crate::log::logger::log_warn!("{}", msg); }

// Panic handler is elsewhere (boot/mod.rs). Alloc error in memory/heap.rs.
