// NØNOS Operating System
// Copyright (C) 2025 NØNOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.
//
//! Boot Sequence and Platform Initialization
//! # Submodules
//! - [`handoff`] - Boot handoff ABI structures
//! - [`nonos_multiboot`] - Multiboot2 parsing and platform detection
//! - [`vga`] - VGA text mode output
//! - [`early`] - Early boot initialization

pub mod early;
pub mod handoff;
pub mod nonos_multiboot;
pub mod vga;

// ============================================================================
// Re-exports
// ============================================================================

// Handoff ABI
pub use handoff::{get_handoff, is_initialized, total_memory};
pub use handoff::{BootHandoffV1, HandoffError, HANDOFF_MAGIC, HANDOFF_VERSION};

// Multiboot support
pub use nonos_multiboot as multiboot;
pub use nonos_multiboot::{
    detect_platform, ConsoleType, MultibootError, MultibootInfo, Platform,
};

// Early boot
pub use early::{serial_print, BootInfo, FramebufferInfo, MemoryDescriptor};

// VGA output
pub use vga::{clear_screen, show_boot_splash, show_panic, write_string};

// ============================================================================
// Public Boot API
// ============================================================================

/// Initialize VGA output and show boot splash
///
/// Called early in boot to provide visual feedback.
#[inline]
pub fn init_vga_output() {
    vga::show_boot_splash();
}

/// Minimal early init before memory allocator is ready
///
/// Pre-heap initialization hook. The actual early boot sequence
/// is implemented in `early.rs` and called from the entry point.
#[inline]
pub fn init_early() {
    // Pre-heap phase: no allocations allowed
    // See early.rs for the actual initialization sequence
}

/// Confirm panic handler is set up
///
/// The panic handler is defined below. This function exists
/// for documentation purposes.
#[inline]
pub fn init_panic_handler() {
    // Panic handler is defined in this module
}

/// Serial print for early diagnostics
///
/// Public wrapper around early::serial_print for macro use.
#[inline]
pub fn _serial_print(args: core::fmt::Arguments) {
    early::serial_print(args);
}

// ============================================================================
// Panic Handler
// ============================================================================

use core::panic::PanicInfo;

/// Kernel panic handler
///
/// Displays panic information on serial and VGA, then halts.
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    // Print to serial
    _serial_print(format_args!("\n!!! KERNEL PANIC !!!\n"));
    _serial_print(format_args!("{}\n", info));

    // Show on VGA
    unsafe {
        vga::show_panic("KERNEL PANIC - See serial for details");
    }

    // Halt forever
    loop {
        unsafe {
            x86_64::instructions::interrupts::disable();
            x86_64::instructions::hlt();
        }
    }
}

// ============================================================================
// Serial Macros
// ============================================================================

/// Print to serial port (early boot diagnostics)
#[macro_export]
macro_rules! serial_print {
    ($($arg:tt)*) => {
        $crate::boot::_serial_print(format_args!($($arg)*))
    };
}

/// Print to serial port with newline
#[macro_export]
macro_rules! serial_println {
    () => { $crate::serial_print!("\n") };
    ($($arg:tt)*) => { $crate::serial_print!("{}\n", format_args!($($arg)*)) };
}
