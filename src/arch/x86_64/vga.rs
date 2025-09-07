//! Minimal VGA text-mode writer for early boot diagnostics.
//!
//! Provides character output to the standard VGA text buffer at
//! `0xb8000`, useful before more advanced console/logging systems
//! are initialized.
//!
//! ## Design
//! - Each cell is 2 bytes: ASCII character + attribute byte.
//! - Attribute controls foreground/background colors.
//! - No scrolling or advanced features here — keep it minimal for now.
//!
//! ## Example
//! ```ignore
//! use crate::arch::x86_64::vga;
//! vga::print("Hello, world!");
//! ```

//use core::ptr::Unique;

/// VGA text buffer physical address.
const VGA_BUFFER: usize = 0xb8000;
/// Number of columns in VGA text mode.
const VGA_WIDTH: usize = 80;
/// Number of rows in VGA text mode.
const VGA_HEIGHT: usize = 25;

/// Default VGA attribute byte (light gray on black).
const DEFAULT_ATTR: u8 = 0x07;

/// Write a string to VGA text buffer starting at top-left corner.
///
/// Overwrites existing contents; no scrolling implemented yet.
pub fn print(s: &str) {
    let buffer = VGA_BUFFER as *mut u8;

    for (i, byte) in s.bytes().enumerate() {
        if i >= VGA_WIDTH * VGA_HEIGHT {
            break;
        }
        unsafe {
            // Character byte
            *buffer.add(i * 2) = byte;
            // Attribute byte
            *buffer.add(i * 2 + 1) = DEFAULT_ATTR;
        }
    }
}

/// Clear the VGA text buffer.
pub fn clear() {
    let buffer = VGA_BUFFER as *mut u8;
    
    for i in 0..(VGA_WIDTH * VGA_HEIGHT) {
        unsafe {
            // Clear character
            *buffer.add(i * 2) = b' ';
            // Reset attribute
            *buffer.add(i * 2 + 1) = DEFAULT_ATTR;
        }
    }
}
