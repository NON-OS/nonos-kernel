//! N0N-OS Kernel - GOP drawing demo (banner + centered NONOS text)
//! Keeps serial logging; draws to a 32-bpp GOP FB (RGB/BGR).

#![no_std]
#![no_main]

use core::panic::PanicInfo;

// -------------------------
// Multiboot2 header (legacy tooling)
// -------------------------
#[repr(C, align(8))]
struct MultibootHeader { magic: u32, architecture: u32, header_length: u32, checksum: u32, end_tag_type: u16, end_tag_flags: u16, end_tag_size: u32 }
#[link_section = ".multiboot_header"]
#[no_mangle]
pub static MULTIBOOT_HEADER: MultibootHeader = MultibootHeader {
    magic: 0x36d76289, architecture: 0, header_length: 24,
    checksum: (0x1_0000_0000u64 - (0x36d7_6289u64 + 0 + 24)) as u32,
    end_tag_type: 0, end_tag_flags: 0, end_tag_size: 8,
};

// -------------------------
// Serial (COM1)
// -------------------------
const SERIAL_PORT: u16 = 0x3F8;

// -------------------------
// Shared ABI: must match bootloader exactly
// -------------------------
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

// Lightweight FB context
#[derive(Clone, Copy)]
struct FbCtx { base: *mut u8, pitch: u32, width: u32, height: u32, fmt: u16 }

// -------------------------
// Kernel entry
// -------------------------
#[no_mangle]
pub extern "sysv64" fn _start(boot_info: *const ZeroStateBootInfo) -> ! {
    // Early serial hello
    unsafe {
        for &b in b"KERNEL\r\n" {
            core::arch::asm!("out dx, al", in("dx") SERIAL_PORT, in("al") b);
        }
    }

    force_serial_init();
    debug_print(b"*** N0N-OS KERNEL ENTRY POINT REACHED! ***");

    let h: &ZeroStateBootInfo = unsafe { &*boot_info };
    dump_fb_info(h);

    let mut fb_ctx: Option<FbCtx> = None;

    if fb_is_usable(h) && h.fb_bpp == 32 && (h.fb_format == fb_format::RGB || h.fb_format == fb_format::BGR) {
        unsafe {
            let fb = h.fb_base_phys as *mut u8;

            // Background (deep brown).
            fb_clear_solid(fb, h.fb_pitch, h.fb_width, h.fb_height, h.fb_format,
                           0x12, 0x1E, 0x36);

            // Top banner (cleaner ratio).
            let banner_h = core::cmp::min(56, h.fb_height); // ~5% on 1080p
            fb_fill_rect(fb, h.fb_pitch, h.fb_width, h.fb_height, h.fb_format,
                         0, 0, h.fb_width, banner_h, 0xFF, 0xFF, 0xFF);

            // Thin accent baseline under banner.
            fb_fill_rect(fb, h.fb_pitch, h.fb_width, h.fb_height, h.fb_format,
                         0, banner_h.saturating_sub(3), h.fb_width, 3,
                         0xF4, 0xA2, 0x42);

            // Static slot where the little progress bar animates.
            let bar_y   = (banner_h / 2).saturating_sub(6);
            let bar_x   = 24;
            let bar_w   = core::cmp::min(420, h.fb_width.saturating_sub(48));
            let bar_h   = 12;
            fb_fill_rect(fb, h.fb_pitch, h.fb_width, h.fb_height, h.fb_format,
                         bar_x, bar_y + bar_h + 4, bar_w, 2, 0xF4, 0xA2, 0x42);

            // Centered “NONOS” in big type.
            draw_center_title(fb, h.fb_pitch, h.fb_width, h.fb_height, h.fb_format,
                              b"NONOS", 6, // scale (8x16 -> 48x96 per glyph)
                              (0xFF, 0xFF, 0xFF), // text color (white)
                              (0x00, 0x00, 0x00), // soft shadow
            );
        }

        debug_print(b"[FB] Drew background + banner + centered title");
        fb_ctx = Some(FbCtx { base: h.fb_base_phys as *mut u8, pitch: h.fb_pitch, width: h.fb_width, height: h.fb_height, fmt: h.fb_format });
    } else {
        debug_print(b"[FB] Not drawing (unsupported mode); serial only");
    }

    debug_print(b"Starting N0N-OS CLI...");
    start_nonos_cli(fb_ctx)
}

// -------------------------
// FB info dump
// -------------------------
fn dump_fb_info(h: &ZeroStateBootInfo) {
    debug_print(b"[FB] Handoff dump:");
    print_hex64(b"  base_phys: 0x", h.fb_base_phys);
    print_u64(b"  size: ", h.fb_size);
    print_u32(b"  pitch: ", h.fb_pitch);
    print_u32(b"  width: ", h.fb_width);
    print_u32(b"  height: ", h.fb_height);
    print_u16(b"  bpp: ", h.fb_bpp);
    print_u16(b"  fmt: ", h.fb_format);

    if fb_is_usable(h) { debug_print(b"[FB] Usable GOP framebuffer provided"); }
    else { debug_print(b"[FB] No usable FB; staying serial-only"); }
}

fn fb_is_usable(h: &ZeroStateBootInfo) -> bool {
    h.fb_base_phys != 0 &&
    h.fb_width > 0 && h.fb_height > 0 &&
    h.fb_size >= (h.fb_pitch as u64) * (h.fb_height as u64)
}

#[inline(always)]
fn pack_u32(fmt: u16, r: u8, g: u8, b: u8) -> u32 {
    match fmt {
        fb_format::RGB => ((r as u32) << 16) | ((g as u32) << 8) | (b as u32),
        fb_format::BGR => ((b as u32) << 16) | ((g as u32) << 8) | (r as u32),
        _ => 0,
    }
}

unsafe fn fb_clear_solid(fb: *mut u8, pitch: u32, width: u32, height: u32, fmt: u16, r: u8, g: u8, b: u8) {
    let px = pack_u32(fmt, r, g, b).to_le_bytes();
    let bpp = 4u32;
    for y in 0..height {
        let mut row = fb.add((y * pitch) as usize);
        for _x in 0..width {
            core::ptr::copy_nonoverlapping(px.as_ptr(), row, 4);
            row = row.add(bpp as usize);
        }
    }
}

unsafe fn fb_fill_rect(
    fb: *mut u8, pitch: u32, width: u32, height: u32, fmt: u16,
    x: u32, y: u32, w: u32, h: u32, r: u8, g: u8, b: u8,
) {
    if x >= width || y >= height { return; }
    let w = core::cmp::min(w, width - x);
    let h = core::cmp::min(h, height - y);
    let px = pack_u32(fmt, r, g, b).to_le_bytes();
    let bpp = 4u32;
    for yy in 0..h {
        let mut row = fb.add(((y + yy) * pitch + x * bpp) as usize);
        for _xx in 0..w {
            core::ptr::copy_nonoverlapping(px.as_ptr(), row, 4);
            row = row.add(bpp as usize);
        }
    }
}

// -------------------------
// Tiny 8×16 font for 'N','O','S' (+ space)
// Each u8 is one row, MSB = leftmost pixel.
// -------------------------
fn glyph_8x16(c: u8) -> Option<&'static [u8; 16]> {
    const N_: [u8;16] = [
        0b1000_0001, 0b1100_0001, 0b1110_0001, 0b1011_0001,
        0b1001_1001, 0b1000_1101, 0b1000_0111, 0b1000_0011,
        0b1000_0111, 0b1000_1101, 0b1001_1001, 0b1011_0001,
        0b1110_0001, 0b1100_0001, 0b1000_0001, 0b0000_0000,
    ];
    const O_: [u8;16] = [
        0b0011_1110, 0b0111_1111, 0b1110_0011, 0b1100_0001,
        0b1100_0001, 0b1100_0001, 0b1100_0001, 0b1100_0001,
        0b1100_0001, 0b1100_0001, 0b1100_0001, 0b1110_0011,
        0b0111_1111, 0b0011_1110, 0b0000_0000, 0b0000_0000,
    ];
    const S_: [u8;16] = [
        0b0011_1110, 0b0111_1111, 0b1110_0001, 0b1100_0000,
        0b1110_0000, 0b0111_1100, 0b0011_1110, 0b0000_1111,
        0b0000_0011, 0b0000_0011, 0b1000_0011, 0b1100_0011,
        0b0111_1111, 0b0011_1110, 0b0000_0000, 0b0000_0000,
    ];
    const SP: [u8;16] = [0;16];
    match c {
        b'N' => Some(&N_), b'O' => Some(&O_), b'S' => Some(&S_), b' ' => Some(&SP),
        _ => None,
    }
}

unsafe fn draw_glyph_scaled(
    fb: *mut u8, pitch: u32, width: u32, height: u32, fmt: u16,
    x: i32, y: i32, glyph: &[u8;16], scale: u32, r: u8, g: u8, b: u8,
) {
    let color = pack_u32(fmt, r, g, b).to_le_bytes();
    let bpp = 4u32;
    for (row, bits) in glyph.iter().enumerate() {
        for sy in 0..scale {
            let yy = y + (row as i32) * (scale as i32) + (sy as i32);
            if yy < 0 || yy as u32 >= height { continue; }
            let mut xx = x;
            for col in 0..8 {
                let on = (bits & (0x80 >> col)) != 0;
                for sx in 0..scale {
                    let px_x = xx + (sx as i32);
                    if on && px_x >= 0 && (px_x as u32) < width {
                        let dst = fb.add((yy as u32 * pitch + (px_x as u32) * bpp) as usize);
                        core::ptr::copy_nonoverlapping(color.as_ptr(), dst, 4);
                    }
                }
                xx += scale as i32;
            }
        }
    }
}

unsafe fn draw_text_scaled(
    fb: *mut u8, pitch: u32, width: u32, height: u32, fmt: u16,
    mut x: i32, y: i32, s: &[u8], scale: u32, r: u8, g: u8, b: u8,
) {
    for &ch in s {
        if let Some(glyph) = glyph_8x16(ch) {
            draw_glyph_scaled(fb, pitch, width, height, fmt, x, y, glyph, scale, r, g, b);
        }
        x += ((8 + 1) * scale) as i32; // 1px tracking at base scale
    }
}

/// Draw large centered title with a tiny shadow offset.
unsafe fn draw_center_title(
    fb: *mut u8, pitch: u32, width: u32, height: u32, fmt: u16,
    text: &[u8], scale: u32, (tr,tg,tb): (u8,u8,u8), (sr,sg,sb): (u8,u8,u8),
) {
    let glyph_w = 8 * scale;
    let track   = 1 * scale;
    let text_w  = (glyph_w + track) * (text.len() as u32) - track;
    let text_h  = 16 * scale;

    let cx = ((width  as i32) - (text_w  as i32)) / 2;
    let cy = ((height as i32) - (text_h as i32)) / 2;

    // Shadow first (slight offset)
    draw_text_scaled(fb, pitch, width, height, fmt, cx + (scale as i32 / 2), cy + (scale as i32 / 2), text, scale, sr, sg, sb);
    // Foreground
    draw_text_scaled(fb, pitch, width, height, fmt, cx, cy, text, scale, tr, tg, tb);
}

// -------------------------
// Serial + tiny print helpers
// -------------------------
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
fn serial_write_byte(byte: u8) { unsafe { core::arch::asm!("out dx, al", in("dx") SERIAL_PORT, in("al") byte, options(nomem, nostack, preserves_flags)); } }
fn serial_write_string(s: &[u8]) { for &b in s { serial_write_byte(b); } }
fn debug_print(s: &[u8]) { serial_write_string(b"[KERNEL] "); serial_write_string(s); serial_write_string(b"\r\n"); }

fn print_u32(prefix: &[u8], v: u32) { serial_write_string(b"[KERNEL] "); serial_write_string(prefix); dec_u64(v as u64); serial_write_string(b"\r\n"); }
fn print_u64(prefix: &[u8], v: u64) { serial_write_string(b"[KERNEL] "); serial_write_string(prefix); dec_u64(v);        serial_write_string(b"\r\n"); }
fn print_u16(prefix: &[u8], v: u16) { serial_write_string(b"[KERNEL] "); serial_write_string(prefix); dec_u64(v as u64); serial_write_string(b"\r\n"); }
fn print_hex64(prefix: &[u8], v: u64) { serial_write_string(b"[KERNEL] "); serial_write_string(prefix); hex_u64(v); serial_write_string(b"\r\n"); }
fn dec_u64(mut n: u64) { let mut buf=[0u8;20]; let mut i=buf.len(); if n==0{serial_write_byte(b'0');return;} while n>0{ i-=1; buf[i]=b'0'+(n%10)as u8; n/=10; } for &b in &buf[i..]{serial_write_byte(b);} }
fn hex_u64(mut n: u64) { const H:&[u8;16]=b"0123456789ABCDEF"; let mut buf=[0u8;16]; for i in (0..16).rev(){ buf[i]=H[(n&0xF)as usize]; n>>=4; } for &b in &buf { serial_write_byte(b); } }

// -------------------------
// Minimal CLI loop (with tiny banner bar animation if FB active)
// -------------------------
fn start_nonos_cli(mut fb: Option<FbCtx>) -> ! {
    debug_print(b">>> N0N-OS CLI READY! <<<");
    debug_print(b"Enter 'help' for commands");
    debug_print(b"nonos# ");

    let mut t: u32 = 0;
    loop {
        unsafe { for _ in 0..5_000_000 { core::arch::asm!("nop"); } }
        t = t.wrapping_add(1);

        if let Some(ctx) = fb {
            // animate slim bar beneath top banner
            let banner_h = core::cmp::min(56, ctx.height);
            let bar_y    = (banner_h / 2).saturating_sub(6);
            let bar_x    = 24;
            let bar_wmax = core::cmp::min(420, ctx.width.saturating_sub(48));
            let bar_h    = 12;
            let phase    = (t % 600) as i32;
            let mut w    = (phase as i64 - 300).abs() as u32;
            if w > bar_wmax { w = bar_wmax; }

            unsafe {
                // clear area
                fb_fill_rect(ctx.base, ctx.pitch, ctx.width, ctx.height, ctx.fmt,
                             bar_x, bar_y, bar_wmax, bar_h, 0xFF, 0xFF, 0xFF);
                // animated fill
                fb_fill_rect(ctx.base, ctx.pitch, ctx.width, ctx.height, ctx.fmt,
                             bar_x, bar_y, w, bar_h, 0x3B, 0x99, 0xFF); // blue-accent
            }
            fb = Some(ctx);
        }

        if t % 120 == 0 { debug_print(b"[N0N-OS] CLI heartbeat - system running"); }
    }
}

// -------------------------
// Panic handler
// -------------------------
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    debug_print(b"*** KERNEL PANIC! ***");
    debug_print(b"Kernel has encountered a fatal error");
    loop { unsafe { core::arch::asm!("hlt"); } }
}
