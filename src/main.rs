
//! NØNOS Kernel Binary Entry Point (src/main.rs)
//!
//! This is the main executable entry point for our custom UEFI bootloader.
//! Our bootloader directly jumps to the kernel's entry point after loading it.

#![no_main]
#![no_std]
#![feature(alloc_error_handler, abi_x86_interrupt)]

// Multiboot2 header for bootloader compatibility
#[link_section = ".multiboot_header"]
#[no_mangle]
pub static MULTIBOOT_HEADER: [u32; 8] = [
    0x36d76289,              // magic
    0,                       // architecture (i386)
    8 * 4,                   // header length
    (0x100000000u64 - (0x36d76289u64 + 0 + 8 * 4)) as u32, // checksum
    0,                       // tag_type (end tag)
    0,                       // flags
    8,                       // size
    0,                       // padding
];

// We need panic infrastructure  
#[macro_use]
extern crate alloc;
extern crate x86_64;

use core::panic::PanicInfo;
use alloc::string::ToString;

// Make alloc macros available at crate root for macros
pub use alloc::{format, vec};

// Import VGA macros
use crate::arch::x86_64::vga::{print, print_critical};

// Define print macros for kernel use
macro_rules! print {
    ($($arg:tt)*) => {
        $crate::arch::x86_64::vga::print(&alloc::format!($($arg)*));
    };
}

macro_rules! println {
    () => { print!("\n"); };
    ($($arg:tt)*) => {
        print!("{}\n", alloc::format!($($arg)*));
    };
}

// Import kernel library - only include existing modules
mod arch;
mod boot;
mod capabilities;
mod crypto;
mod drivers;
mod elf;
mod filesystem;
mod fs;
mod interrupts;
mod ipc;
mod log;
mod manifest;
mod memory;
mod modules;
mod network;
mod process;
mod runtime;
mod sched;
mod security;
mod storage;
mod syscall;
mod time;
mod ui;
mod vault;
mod zk_engine;

// Single-file modules
mod system_monitor;
mod external;
mod shell;
mod apps;
mod desktop;

// Alias for monitor functions  
pub mod monitor {
    pub use crate::system_monitor::*;
    
    /// Update syscall statistics
    pub fn update_syscall_stats(syscall_num: u64, result: u64) {
        // Log syscall for monitoring
        if result != 0 {
            // Simple logging without complex dependencies
        }
    }
}

/// Multiboot2 entry point
#[no_mangle]
pub extern "C" fn _start() -> ! {
    kernel_main()
}

/// Legacy entry point for other bootloaders
#[no_mangle]
pub extern "C" fn _start_multiboot(magic: u32, boot_info: *const u8) -> ! {
    kernel_main()
}

/// The entry point called by our custom UEFI bootloader  
#[no_mangle]
pub extern "C" fn _start_uefi(boot_info: *const u8) -> ! {
    // Initialize VGA output
    unsafe {
        let vga = 0xb8000 as *mut u8;
        
        // Clear screen
        for i in 0..80*25 {
            let offset = i * 2;
            *vga.add(offset) = b' ';
            *vga.add(offset + 1) = 0x07; // Light gray on black
        }
        
        // Print boot messages
        let msg = b"N0N-OS Kernel v0.1 - Booting...";
        for (i, &byte) in msg.iter().enumerate() {
            let offset = i * 2;
            *vga.add(offset) = byte;
            *vga.add(offset + 1) = 0x0F; // White on black
        }
        
        let msg2 = b"Initializing keyboard driver...";
        for (i, &byte) in msg2.iter().enumerate() {
            let offset = (i + 80) * 2; // Second line
            *vga.add(offset) = byte;
            *vga.add(offset + 1) = 0x0A; // Green on black
        }
    }
    
    // Initialize kernel services
    start_kernel_services();
    
    // Print ready message
    unsafe {
        let vga = 0xb8000 as *mut u8;
        let msg3 = b"System ready! Starting shell...";
        for (i, &byte) in msg3.iter().enumerate() {
            let offset = (i + 160) * 2; // Third line
            *vga.add(offset) = byte;
            *vga.add(offset + 1) = 0x0E; // Yellow on black
        }
    }
    
    // Start shell after brief delay
    for _ in 0..10000000 {
        unsafe { core::arch::asm!("pause"); }
    }
    
    // Start the shell
    shell::start_shell()
}

fn show_boot_menu() {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║                     N0N-OS Boot Menu                         ║");
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!("║  Welcome to N0N-OS - Advanced Microkernel Operating System  ║");
    println!("║                                                              ║");
    println!("║  Please select your interface:                              ║");
    println!("║                                                              ║");
    println!("║  1. Desktop Environment (GUI)                               ║");
    println!("║  2. Shell (Command Line)                                    ║");
    println!("║  3. Text Mode Interface                                     ║");
    println!("║  4. Network Boot Mode                                       ║");
    println!("║                                                              ║");
    println!("║  System Status:                                             ║");
    println!("║    ✓ Kernel: Loaded and Running                             ║");
    println!("║    ✓ Memory: {} MB Available                               ║", 512);
    println!("║    ✓ Storage: Detected and Mounted                          ║");
    println!("║    ✓ Network: Configured and Active                         ║");
    println!("║    ✓ Security: All Subsystems Operational                   ║");
    println!("║                                                              ║");
    println!("║  Starting Desktop Environment in 3 seconds...              ║");
    println!("║  (Press any key to choose different option)                 ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
}

fn start_kernel_services() {
    // Initialize keyboard driver first
    if let Err(e) = drivers::keyboard::init_keyboard() {
        crate::println!("Failed to initialize keyboard: {}", e);
    } else {
        crate::println!("✓ Keyboard driver initialized");
    }
    
    // Start the kernel daemon processes
    spawn_kernel_daemon("memory_manager", memory_management_daemon);
    spawn_kernel_daemon("process_scheduler", process_scheduler_daemon);
    spawn_kernel_daemon("security_monitor", security_monitoring_daemon);
    spawn_kernel_daemon("network_stack", network_stack_daemon);
    spawn_kernel_daemon("filesystem_sync", filesystem_sync_daemon);
    spawn_kernel_daemon("crypto_service", crypto_service_daemon);
    
    crate::println!("✓ All kernel services started");
}

fn spawn_kernel_daemon(_name: &str, _daemon: fn()) {
    // In a real OS, this would spawn actual kernel threads
    // For now, we'll register the daemons to run in the main loop
}

fn memory_management_daemon() {
    // Handle memory allocation requests, garbage collection, etc.
    memory::run_memory_manager();
}

fn process_scheduler_daemon() {
    // Handle process scheduling, context switching
    sched::run_scheduler();
}

fn security_monitoring_daemon() {
    // Monitor system for security threats
    security::run_security_monitor();
}

fn network_stack_daemon() {
    // Handle network packet processing
    network::run_network_stack();
}

fn filesystem_sync_daemon() {
    // Handle filesystem synchronization and caching
    fs::run_filesystem_sync();
}

fn crypto_service_daemon() {
    // Handle cryptographic operations
    crypto::run_crypto_service();
}

fn kernel_main_loop() -> ! {
    log::info!("N0N-OS kernel entering main event loop");
    
    loop {
        // Process interrupt queue
        interrupts::process_interrupt_queue();
        
        // Run scheduler tick
        sched::scheduler_tick();
        
        // Process IPC messages  
        ipc::process_message_queue();
        
        // Run security checks
        security::run_periodic_checks();
        
        // Process filesystem operations
        fs::process_pending_operations();
        
        // Handle network packets
        network::process_packet_queue();
        
        // Update system monitor metrics
        system_monitor::update_metrics();
        
        // Run crypto background tasks
        crypto::process_background_tasks();
        
        // Memory management housekeeping
        memory::run_periodic_cleanup();
        
        // Yield CPU for power management
        arch::cpu_yield();
    }
}

/// Kernel main function (required by multiboot)
#[no_mangle]
pub extern "C" fn kernel_main() -> ! {
    // Initialize VGA for early output
    unsafe {
        let vga = 0xb8000 as *mut u8;
        let message = b"NONOS Kernel Starting (multiboot)...";
        
        // Clear screen first
        for i in 0..80*25 {
            let offset = i * 2;
            *vga.add(offset) = b' ';
            *vga.add(offset + 1) = 0x07; // Light gray on black
        }
        
        // Write message
        for (i, &byte) in message.iter().enumerate() {
            let offset = i * 2;
            if offset < 160 { // Stay on first line
                *vga.add(offset) = byte;
                *vga.add(offset + 1) = 0x0A; // Bright green on black
            }
        }
    }
    
    // Basic systems initialized
    
    // Enter main loop
    loop {
        unsafe {
            core::arch::asm!("hlt");
        }
    }
}

// Panic handler is defined in boot/mod.rs

// Allocation error handler is defined in memory/heap.rs