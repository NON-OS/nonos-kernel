//! NØNOS Freestanding Hardware Entrypoint 
//!
//! This is the lowest level physical entry point for bare-metal execution.
//! Used only if booting without `bootloader` or UEFI handoff. It initializes
//! minimal console output and traps panics directly to VGA memory. This is
//! effectively the real-mode-to-long-mode bridge fallback before `lib.rs`
//! transitions into ZeroState runtime.

#![no_main]
#![no_std]
#![feature(panic_info_message, asm_const)]

use core::panic::PanicInfo;

/// Direct access to VGA text buffer - higher-half virtual address
const VGA_BUFFER: *mut u8 = 0xFFFF8000000B8000 as *mut u8;
const SCREEN_WIDTH: usize = 80;
const SCREEN_HEIGHT: usize = 25;
const BYTES_PER_CHAR: usize = 2;

/// Hardware startup entry point. This bypasses all runtime init and executes
/// directly from CPU reset vector into high-half kernel (or linked ELF).
#[no_mangle]
pub extern "C" fn _start() -> ! {
    vga_clear();
    vga_print("\n[NONOS: FREESTANDING MODE]\n");
    vga_print("RAM-Resident Bootloader Interface Initialized\n");
    vga_print("Awaiting secure jump to `kernel_main()`...\n");

    // Here we would normally jump to kernel_main() once paging & stack are valid
    loop {}
}

/// Global position tracker for VGA output
static mut VGA_POSITION: usize = 0;

/// Prints a string to VGA text mode buffer
fn vga_print(msg: &str) {
    unsafe {
        for byte in msg.bytes() {
            if byte == b'\n' {
                // Move to next line
                VGA_POSITION = (VGA_POSITION / SCREEN_WIDTH + 1) * SCREEN_WIDTH;
                if VGA_POSITION >= SCREEN_WIDTH * SCREEN_HEIGHT {
                    vga_scroll();
                    VGA_POSITION = (SCREEN_HEIGHT - 1) * SCREEN_WIDTH;
                }
            } else {
                // Write character
                let offset = VGA_POSITION * BYTES_PER_CHAR;
                *VGA_BUFFER.add(offset) = byte;
                *VGA_BUFFER.add(offset + 1) = 0x0F; // white on black
                
                VGA_POSITION += 1;
                if VGA_POSITION >= SCREEN_WIDTH * SCREEN_HEIGHT {
                    vga_scroll();
                    VGA_POSITION = (SCREEN_HEIGHT - 1) * SCREEN_WIDTH;
                }
            }
        }
    }
}

/// Scroll VGA buffer up one line
fn vga_scroll() {
    unsafe {
        // Copy all lines up one row
        for row in 1..SCREEN_HEIGHT {
            let src = VGA_BUFFER.add(row * SCREEN_WIDTH * BYTES_PER_CHAR);
            let dst = VGA_BUFFER.add((row - 1) * SCREEN_WIDTH * BYTES_PER_CHAR);
            core::ptr::copy(src, dst, SCREEN_WIDTH * BYTES_PER_CHAR);
        }
        
        // Clear last line
        let last_line = VGA_BUFFER.add((SCREEN_HEIGHT - 1) * SCREEN_WIDTH * BYTES_PER_CHAR);
        for i in 0..SCREEN_WIDTH {
            *last_line.add(i * BYTES_PER_CHAR) = b' ';
            *last_line.add(i * BYTES_PER_CHAR + 1) = 0x0F;
        }
    }
}

/// Zero-clears the VGA console to black
fn vga_clear() {
    unsafe {
        for i in 0..(SCREEN_WIDTH * SCREEN_HEIGHT) {
            let offset = i * BYTES_PER_CHAR;
            *VGA_BUFFER.add(offset) = b' ';
            *VGA_BUFFER.add(offset + 1) = 0x00;
        }
        VGA_POSITION = 0; // Reset position
    }
}

/// Trap for panics occurring before the full kernel initializes
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    vga_print("\n\n[KERNEL PANIC]\n");
    vga_print("panic: hardware fault\n");
    loop {}
}
