//! N0NOS Kernel 

#![no_std]
#![no_main]

// Multiboot header for GRUB compatibility
#[repr(C, align(4))]
pub struct MultibootHeader {
    magic: u32,
    flags: u32,
    checksum: u32,
}

#[link_section = ".multiboot"]
#[no_mangle]
pub static MULTIBOOT_HEADER: MultibootHeader = MultibootHeader {
    magic: 0x1BADB002,
    flags: 0x00000000,
    checksum: (0_u32).wrapping_sub(0x1BADB002u32).wrapping_sub(0x00000000u32),
};

// Hardware constants
const VGA_BUFFER: *mut u8 = 0xb8000 as *mut u8;
const SERIAL_PORT: u16 = 0x3f8;

// Kernel entry point
#[no_mangle]
pub extern "C" fn _start(_handoff_info: u64) -> ! {
    init_serial();
    clear_screen();
    
    print_at(b"N0N-OS Kernel v0.2.0", 2, 0x0F);
    print_at(b"Production kernel loaded", 4, 0x0A);
    
    debug_print(b"Kernel initialized successfully");
    
    kernel_main()
}

fn init_serial() {
    unsafe {
        core::arch::asm!("out dx, al", in("dx") SERIAL_PORT + 1, in("al") 0x00u8);
        core::arch::asm!("out dx, al", in("dx") SERIAL_PORT + 3, in("al") 0x80u8);
        core::arch::asm!("out dx, al", in("dx") SERIAL_PORT + 0, in("al") 0x03u8);
        core::arch::asm!("out dx, al", in("dx") SERIAL_PORT + 1, in("al") 0x00u8);
        core::arch::asm!("out dx, al", in("dx") SERIAL_PORT + 3, in("al") 0x03u8);
        core::arch::asm!("out dx, al", in("dx") SERIAL_PORT + 2, in("al") 0xC7u8);
        core::arch::asm!("out dx, al", in("dx") SERIAL_PORT + 4, in("al") 0x0Bu8);
    }
}

fn serial_write_byte(byte: u8) {
    unsafe {
        loop {
            let mut status: u8;
            core::arch::asm!("in al, dx", in("dx") SERIAL_PORT + 5, out("al") status);
            if (status & 0x20) != 0 { break; }
        }
        core::arch::asm!("out dx, al", in("dx") SERIAL_PORT, in("al") byte);
    }
}

fn debug_print(s: &[u8]) {
    for &byte in b"[KERNEL] " {
        serial_write_byte(byte);
    }
    for &byte in s {
        serial_write_byte(byte);
    }
    for &byte in b"\r\n" {
        serial_write_byte(byte);
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

fn kernel_main() -> ! {
    debug_print(b"Kernel running");
    
    let mut counter = 0u32;
    loop {
        if counter % 100000000 == 0 {
            debug_print(b"System operational");
        }
        
        counter = counter.wrapping_add(1);
        
        unsafe {
            core::arch::asm!("hlt");
        }
    }
}

#[no_mangle]
pub extern "C" fn memset(dest: *mut u8, val: i32, len: usize) -> *mut u8 {
    unsafe {
        for i in 0..len {
            *dest.add(i) = val as u8;
        }
    }
    dest
}

#[no_mangle]
pub extern "C" fn memcmp(ptr1: *const u8, ptr2: *const u8, len: usize) -> i32 {
    unsafe {
        for i in 0..len {
            let a = *ptr1.add(i);
            let b = *ptr2.add(i);
            if a != b {
                return a as i32 - b as i32;
            }
        }
    }
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    debug_print(b"KERNEL PANIC");
    loop {
        unsafe {
            core::arch::asm!("hlt");
        }
    }
}