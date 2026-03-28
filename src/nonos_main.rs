// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

#![no_std]
#![no_main]

extern crate alloc;
extern crate nonos_kernel;

use core::arch::{asm, naked_asm};
use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};

mod manifest_embed { include!(concat!(env!("OUT_DIR"), "/manifest_data.rs")); }
pub use manifest_embed::*;

use nonos_kernel::boot::handoff::{init_handoff, BootHandoffV1};
use nonos_kernel::graphics::{framebuffer, desktop, cursor, window};
use nonos_kernel::sys::{gdt, idt, serial, clock, apic};
use nonos_kernel::entry::{network, security, desktop_loop, fallback};
use nonos_kernel::{interrupts, storage, mem, bus, input};

static HANDOFF_PTR: AtomicU64 = AtomicU64::new(0);
static SSE_ENABLED: AtomicBool = AtomicBool::new(false);

#[unsafe(naked)]
#[no_mangle]
#[link_section = ".text._start"]
pub extern "C" fn _start() -> ! {
    naked_asm!(
        "cli", "cld", "push rdi", "mov dx, 0x3F8", "mov al, 'K'", "out dx, al", "mov al, 10", "out dx, al",
        "finit", "mov rax, cr0", "and eax, 0xFFFFFFFB", "or eax, 0x00000022", "mov cr0, rax",
        "mov rax, cr4", "or eax, 0x00000600", "mov cr4, rax",
        "mov dx, 0x3F8", "mov al, 'S'", "out dx, al", "mov al, 10", "out dx, al",
        "pop rdi", "call {rust_entry}", "2:", "cli", "hlt", "jmp 2b",
        rust_entry = sym kernel_entry,
    )
}

#[no_mangle]
extern "C" fn kernel_entry(handoff_ptr: u64) -> ! {
    HANDOFF_PTR.store(handoff_ptr, Ordering::SeqCst);
    SSE_ENABLED.store(true, Ordering::SeqCst);
    init_core_systems();
    if handoff_ptr == 0 { serial::println(b"[NONOS] CRITICAL: No handoff from bootloader!"); fallback::vga_fallback(); }
    let handoff = match unsafe { init_handoff(handoff_ptr) } {
        Ok(h) => { serial::println(b"[NONOS] Boot handoff validated"); h }
        Err(e) => { serial::println(b"[NONOS] CRITICAL: Handoff validation failed!"); serial::print(b"[NONOS] Error: "); serial::println(e.as_str().as_bytes()); fallback::vga_fallback(); }
    };
    security::log_security_status(handoff);
    if handoff.fb.ptr != 0 { init_graphics(handoff); run_desktop(); }
    else { serial::println(b"[NONOS] No framebuffer - VGA fallback"); fallback::vga_fallback(); }
}

fn init_core_systems() {
    serial::init(); serial::println(b"[NONOS] Kernel entry - SSE enabled");
    nonos_kernel::arch::x86_64::time::timer::init_boot_time();
    unsafe { gdt::setup(); } serial::println(b"[NONOS] GDT configured");
    unsafe { idt::setup(); } serial::println(b"[NONOS] Early IDT configured");
    nonos_kernel::memory::heap::manager::init_bootstrap(); serial::println(b"[NONOS] Global allocator initialized");
    mem::heap::init(); serial::println(b"[NONOS] Heap initialized");
    interrupts::init_idt(); serial::println(b"[NONOS] Full IDT loaded with handlers");
    apic::init(); serial::println(b"[NONOS] APIC initialized");
    input::keyboard::init(); input::mouse::init(); serial::println(b"[NONOS] Input devices initialized");
    apic::setup_keyboard_irq(); apic::setup_mouse_irq(); serial::println(b"[NONOS] Keyboard and mouse IRQs enabled");
    unsafe { asm!("sti", options(nomem, nostack)); } serial::println(b"[NONOS] Interrupts enabled");
    bus::pci::init(); serial::println(b"[NONOS] PCI bus enumerated");
    if let Ok(()) = nonos_kernel::drivers::init_virtio_rng() { serial::println(b"[NONOS] VirtIO-RNG initialized - hardware entropy available"); }
    else { serial::println(b"[NONOS] VirtIO-RNG not found - using software RNG only"); }
}

fn init_graphics(handoff: &BootHandoffV1) {
    serial::print(b"[NONOS] Display: "); serial::print_dec(handoff.fb.width as u64); serial::print(b"x"); serial::print_dec(handoff.fb.height as u64); serial::println(b"");
    let fb_phys = nonos_kernel::memory::PhysAddr::new(handoff.fb.ptr);
    let fb_virt = match nonos_kernel::memory::mmio::map_framebuffer(fb_phys, handoff.fb.size as usize) {
        Ok(va) => { serial::print(b"[NONOS] Framebuffer mapped: phys="); serial::print_hex(handoff.fb.ptr); serial::print(b" -> virt="); serial::print_hex(va.as_u64()); serial::println(b""); va.as_u64() }
        Err(_) => { serial::println(b"[NONOS] Framebuffer mapping failed, using direct phys addr"); handoff.fb.ptr }
    };
    framebuffer::init(fb_virt, handoff.fb.width, handoff.fb.height, handoff.fb.stride); serial::println(b"[NONOS] Framebuffer initialized");
    if framebuffer::init_double_buffer() { serial::println(b"[NONOS] Double buffering enabled"); } else { serial::println(b"[NONOS] Double buffering failed - using direct rendering"); }
    input::set_screen_bounds_unified(handoff.fb.width, handoff.fb.height);
    serial::println(b"[NONOS] Scanning for I2C HID devices..."); let i2c_hid_count = input::i2c_hid::init();
    if i2c_hid_count > 0 { serial::println(b"[NONOS] I2C HID touchpad found!"); } else { serial::println(b"[NONOS] No I2C HID devices found"); }
    input::usb_hid::init(); serial::println(b"[NONOS] USB HID initialized");
    clock::init(handoff.timing.tsc_hz, handoff.timing.unix_epoch_ms); serial::println(b"[NONOS] Clock initialized");
    storage::usb_msc::init(); storage::fat32::init(); serial::println(b"[NONOS] Storage initialized");
    serial::println(b"[VFS] Starting VFS init..."); nonos_kernel::fs::vfs::init_vfs(); serial::println(b"[VFS] VFS core initialized");
    let _ = nonos_kernel::fs::cryptofs::init_cryptofs(1024 * 1024, 4096); serial::println(b"[VFS] CryptoFS initialized");
    let _ = nonos_kernel::fs::ramfs::init_nonos_filesystem(); serial::println(b"[VFS] RamFS initialized");
    nonos_kernel::fs::cache::init_all_caches(); serial::println(b"[NONOS] VFS initialized");
    nonos_kernel::sys::settings::init(); nonos_kernel::sys::settings::init_hostname(); serial::println(b"[NONOS] Settings initialized");
    if storage::fat32::fs_count() > 0 {
        if nonos_kernel::sys::settings::load_from_disk() { serial::println(b"[NONOS] Settings loaded from disk"); }
        if nonos_kernel::sys::settings::network::load_from_disk() { serial::println(b"[NONOS] Network settings loaded from disk"); }
    }
    nonos_kernel::sys::settings::network::init();
    nonos_kernel::process::init_process_management(); serial::println(b"[NONOS] Process management initialized");
    nonos_kernel::agents::init(); serial::println(b"[NONOS] AI Agents initialized");
    nonos_kernel::sdk::init(); serial::println(b"[NONOS] SDK and Marketplace initialized");
    network::init_network();
    nonos_kernel::graphics::backgrounds::init_wallpaper_system(); serial::println(b"[NONOS] Starting desktop...");
    desktop::refresh_desktop_icons(); desktop::draw_all();
    let (mx, my) = input::mouse_position_unified(); cursor::draw(mx, my); framebuffer::swap_buffers(); serial::println(b"[NONOS] Desktop drawn");
    match nonos_kernel::vault::nonos_vault::initialize_vault() { Ok(()) => serial::println(b"[NONOS] Vault system initialized"), Err(e) => { serial::print(b"[NONOS] Vault init failed: "); serial::println(e.as_bytes()); } }
    serial::println(b"[NONOS] ZK engine ready (lazy init)");
}

fn run_desktop() -> ! {
    serial::println(b"[NONOS] Desktop ready");
    let (mut old_mx, mut old_my) = input::mouse_position_unified();
    framebuffer::double_buffer::disable(); cursor::draw(old_mx, old_my); framebuffer::double_buffer::enable();
    let mut last_clock_update = nonos_kernel::sys::clock::unix_ms();
    serial::println(b"[NONOS] Entering main loop");
    loop {
        handle_dialogs();
        desktop_loop::handle_keyboard_input();
        desktop_loop::handle_mouse_input(&mut old_mx, &mut old_my);
        nonos_kernel::network::poll_network();
        nonos_kernel::apps::ecosystem::browser::poll_navigation();
        if nonos_kernel::graphics::window::settings::take_background_changed() { desktop_loop::set_needs_redraw(); }
        if nonos_kernel::graphics::window::ecosystem::state::take_content_changed() { desktop_loop::set_needs_redraw(); }
        unsafe {
            if desktop_loop::NEEDS_REDRAW {
                desktop::redraw_background(); window::draw_all();
                nonos_kernel::graphics::window::context_menu::draw();
                cursor::draw(old_mx, old_my); framebuffer::swap_buffers();
                desktop_loop::NEEDS_REDRAW = false;
            }
        }
        let now_ms = nonos_kernel::sys::clock::unix_ms();
        if now_ms >= last_clock_update + 1000 { last_clock_update = now_ms; desktop::update_clock(); desktop_loop::set_needs_redraw(); }
        for _ in 0..100 { unsafe { asm!("pause", options(nomem, nostack)); } }
    }
}

fn handle_dialogs() {
    if window::is_dialog_active() {
        let result = window::get_dialog_result();
        if result != window::dialog_result::RESULT_NONE {
            let callback = window::get_dialog_input_callback();
            if result == window::dialog_result::RESULT_OK {
                let text = window::get_dialog_input_text();
                if !text.is_empty() {
                    match callback {
                        cb if cb == window::dialog_callback::INPUT_CB_DESKTOP_NEW_FOLDER => { desktop::create_desktop_folder(text); }
                        cb if cb == window::dialog_callback::INPUT_CB_DESKTOP_NEW_FILE => { desktop::create_desktop_file(text); }
                        cb if cb == window::dialog_callback::INPUT_CB_FM_NEW_FOLDER => { let _ = window::fm_create_folder(text); }
                        _ => {}
                    }
                }
            }
            window::close_dialog();
            desktop_loop::set_needs_redraw();
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn memcpy(d: *mut u8, s: *const u8, n: usize) -> *mut u8 {
    unsafe { let mut i = 0; while i < n { *d.add(i) = *s.add(i); i += 1; } d }
}

#[no_mangle]
pub unsafe extern "C" fn memset(d: *mut u8, c: i32, n: usize) -> *mut u8 {
    unsafe { let mut i = 0; while i < n { *d.add(i) = c as u8; i += 1; } d }
}

#[no_mangle]
pub unsafe extern "C" fn memcmp(a: *const u8, b: *const u8, n: usize) -> i32 {
    unsafe { let mut i = 0; while i < n { if *a.add(i) != *b.add(i) { return (*a.add(i) as i32) - (*b.add(i) as i32); } i += 1; } 0 }
}

#[no_mangle]
pub unsafe extern "C" fn memmove(d: *mut u8, s: *const u8, n: usize) -> *mut u8 {
    unsafe { if (d as usize) < (s as usize) { memcpy(d, s, n) } else { let mut i = n; while i > 0 { i -= 1; *d.add(i) = *s.add(i); } d } }
}
