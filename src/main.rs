#![no_std]
#![no_main]

mod gfx;
mod splash;

use core::panic::PanicInfo;
use gfx::{Fb, FMT_RGB, FMT_BGR};

// ===== Shared ABI (must match bootloader) =====
pub mod fb_format {
    pub const UNKNOWN: u16  = 0;
    pub const RGB: u16      = 1;
    pub const BGR: u16      = 2;
    pub const BITMASK: u16  = 3;
    pub const BLTONLY: u16  = 4;
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ZeroStateBootInfo {
    pub magic: u64,
    pub abi_version: u16,
    pub hdr_size: u16,
    pub boot_flags: u32,

    pub capsule_base: u64,
    pub capsule_size: u64,
    pub capsule_hash: [u8; 32],

    pub memory_start: u64,
    pub memory_size: u64,

    pub entropy: [u8; 32],
    pub rtc_utc: [u8; 8],
    pub reserved: [u8; 8],

    pub fb_base_phys: u64,
    pub fb_size: u64,
    pub fb_pitch: u32,
    pub fb_width: u32,
    pub fb_height: u32,
    pub fb_bpp: u16,
    pub fb_format: u16,
}

// ===== Serial (COM1) =====
const SERIAL_PORT: u16 = 0x3F8;

#[no_mangle]
pub extern "C" fn _start(boot_info: *const ZeroStateBootInfo) -> ! {
    unsafe {
        core::arch::asm!("out dx, al", in("dx") SERIAL_PORT, in("al") b'K');
        core::arch::asm!("out dx, al", in("dx") SERIAL_PORT, in("al") b'\r');
        core::arch::asm!("out dx, al", in("dx") SERIAL_PORT, in("al") b'\n');
    }
    force_serial_init();
    debug_print(b"*** N0N-OS KERNEL ENTRY POINT REACHED! ***");

    let h: &ZeroStateBootInfo = unsafe { &*boot_info };
    debug_print(b"[FB] Handoff dump:");
    print_hex64(b"  base_phys: 0x", h.fb_base_phys);
    print_u64  (b"  size: ",          h.fb_size);
    print_u32  (b"  pitch: ",         h.fb_pitch);
    print_u32  (b"  width: ",         h.fb_width);
    print_u32  (b"  height: ",        h.fb_height);
    print_u16  (b"  bpp: ",           h.fb_bpp);
    print_u16  (b"  fmt: ",           h.fb_format);

    print_hex64(b"[MEM] memory_start: 0x", h.memory_start);
    print_u64 (b"[MEM] memory_size : ",     h.memory_size);

    // Build FB view + render splash
    let fb = Fb {
        base: h.fb_base_phys as *mut u8,
        size: h.fb_size as usize,
        pitch: h.fb_pitch,
        w: h.fb_width,
        h: h.fb_height,
        bpp: h.fb_bpp,
        fmt: match h.fb_format { fb_format::RGB => FMT_RGB, _ => FMT_BGR },
    };

    if fb.is_valid() {
        unsafe { splash::render_dashboard(&fb); }
        debug_print(b"[FB] Dashboard rendered");
    } else {
        debug_print(b"[FB] No valid framebuffer; serial-only");
    }

    start_nonos_cli()
}

// ===== Serial utils =====
fn force_serial_init() {
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
    unsafe { core::arch::asm!("out dx, al", in("dx") SERIAL_PORT, in("al") byte, options(nomem, nostack, preserves_flags)); }
}
fn serial_write_string(s: &[u8]) { for &b in s { serial_write_byte(b); } }
fn debug_print(s: &[u8]) { serial_write_string(b"[KERNEL] "); serial_write_string(s); serial_write_string(b"\r\n"); }
fn print_u32(prefix: &[u8], v: u32) { serial_write_string(b"[KERNEL] "); serial_write_string(prefix); dec_u64(v as u64); serial_write_string(b"\r\n"); }
fn print_u64(prefix: &[u8], v: u64) { serial_write_string(b"[KERNEL] "); serial_write_string(prefix); dec_u64(v);        serial_write_string(b"\r\n"); }
fn print_u16(prefix: &[u8], v: u16) { serial_write_string(b"[KERNEL] "); serial_write_string(prefix); dec_u64(v as u64); serial_write_string(b"\r\n"); }
fn print_hex64(prefix: &[u8], v: u64) { serial_write_string(b"[KERNEL] "); serial_write_string(prefix); hex_u64(v); serial_write_string(b"\r\n"); }
fn dec_u64(mut n: u64) {
    let mut buf = [0u8; 20]; let mut i = buf.len();
    if n == 0 { serial_write_byte(b'0'); return; }
    while n > 0 { i -= 1; buf[i] = b'0' + (n % 10) as u8; n /= 10; }
    for &b in &buf[i..] { serial_write_byte(b); }
}
fn hex_u64(mut n: u64) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut buf = [0u8; 16];
    for i in (0..16).rev() { buf[i] = HEX[(n & 0xF) as usize]; n >>= 4; }
    for &b in &buf { serial_write_byte(b); }
}

// ===== Minimal CLI loop =====
fn start_nonos_cli() -> ! {
    debug_print(b">>> N0N-OS CLI READY! <<<");
    debug_print(b"Enter 'help' for commands");
    debug_print(b"nonos# ");
    let mut counter = 0u64;
    loop {
        unsafe { for _ in 0..10_000_000 { core::arch::asm!("nop"); } }
        counter += 1;
        if counter % 100 == 0 { debug_print(b"[N0N-OS] CLI heartbeat - system running"); }
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    debug_print(b"*** KERNEL PANIC! ***");
    debug_print(b"Kernel has encountered a fatal error");
    loop { unsafe { core::arch::asm!("hlt"); } }
}
