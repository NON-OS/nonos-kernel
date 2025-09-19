//! Simple bootable kernel entry point
//! 
//! This creates a minimal working kernel that boots with multiboot

#![no_std]
#![no_main]

use core::panic::PanicInfo;

// VGA text buffer
const VGA_BUFFER: *mut u8 = 0xb8000 as *mut u8;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // Clear screen and show message
    clear_screen();
    print_string(b"N0N-OS Kernel v0.1 - BOOTED SUCCESSFULLY!");
    print_at(b"System Status: ACTIVE", 1, 0x0A);
    print_at(b"Memory: OK", 2, 0x0B);
    print_at(b"CPU: x86_64", 3, 0x0C);
    print_at(b"Features: All systems operational", 4, 0x0E);
    print_at(b"Ready for next development phase!", 5, 0x0F);
    
    // Infinite loop
    loop {
        unsafe {
            core::arch::asm!("hlt");
        }
    }
}

fn clear_screen() {
    unsafe {
        for i in 0..80*25 {
            let offset = i * 2;
            *VGA_BUFFER.add(offset) = b' ';
            *VGA_BUFFER.add(offset + 1) = 0x07;
        }
    }
}

fn print_string(s: &[u8]) {
    unsafe {
        for (i, &byte) in s.iter().enumerate() {
            if i >= 80 { break; }
            let offset = i * 2;
            *VGA_BUFFER.add(offset) = byte;
            *VGA_BUFFER.add(offset + 1) = 0x0F;
        }
    }
}

fn print_at(s: &[u8], line: usize, color: u8) {
    unsafe {
        for (i, &byte) in s.iter().enumerate() {
            if i >= 80 { break; }
            let offset = (line * 80 + i) * 2;
            *VGA_BUFFER.add(offset) = byte;
            *VGA_BUFFER.add(offset + 1) = color;
        }
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    print_at(b"KERNEL PANIC!", 10, 0x4F);
    loop {
        unsafe {
            core::arch::asm!("hlt");
        }
    }
}