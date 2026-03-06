// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
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

#![no_std]
#![no_main]

extern crate alloc;
extern crate nonos_kernel;

use core::arch::{asm, naked_asm};
use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};

mod manifest_embed {
    include!(concat!(env!("OUT_DIR"), "/manifest_data.rs"));
}
pub use manifest_embed::*;

use nonos_kernel::boot::handoff::{init_handoff, BootHandoffV1};
use nonos_kernel::graphics::{framebuffer, desktop, cursor, window};
use nonos_kernel::input::{keyboard, mouse};
use nonos_kernel::sys::{gdt, idt, serial, clock, apic};
use nonos_kernel::interrupts;
use nonos_kernel::storage;
use nonos_kernel::mem;
use nonos_kernel::bus;

static HANDOFF_PTR: AtomicU64 = AtomicU64::new(0);
static SSE_ENABLED: AtomicBool = AtomicBool::new(false);

static mut PREV_LEFT_BUTTON: bool = false;
static mut PREV_RIGHT_BUTTON: bool = false;
pub static mut NEEDS_REDRAW: bool = false;
static mut WAS_DRAGGING: bool = false;

#[unsafe(naked)]
#[no_mangle]
#[link_section = ".text._start"]
pub extern "C" fn _start() -> ! {
    naked_asm!(
        "push rdi",
        "mov dx, 0x3F8",
        "mov al, 'K'",
        "out dx, al",
        "mov al, 10",
        "out dx, al",
        "mov rax, cr0",
        "and ax, 0xFFFB",
        "or ax, 0x2",
        "mov cr0, rax",
        "mov rax, cr4",
        "or ax, 0x600",
        "mov cr4, rax",
        "mov dx, 0x3F8",
        "mov al, 'S'",
        "out dx, al",
        "mov al, 10",
        "out dx, al",
        "pop rdi",
        "call {rust_entry}",
        "2:",
        "hlt",
        "jmp 2b",
        rust_entry = sym kernel_entry,
    )
}

#[no_mangle]
extern "C" fn kernel_entry(handoff_ptr: u64) -> ! {
    HANDOFF_PTR.store(handoff_ptr, Ordering::SeqCst);
    SSE_ENABLED.store(true, Ordering::SeqCst);

    serial::init();
    serial::println(b"[NONOS] Kernel entry - SSE enabled");

    unsafe { gdt::setup(); }
    unsafe { gdt::enable_iopl(); }
    serial::println(b"[NONOS] GDT configured");

    unsafe { idt::setup(); }
    serial::println(b"[NONOS] Early IDT configured");

    nonos_kernel::memory::heap::manager::init_bootstrap();
    serial::println(b"[NONOS] Global allocator initialized");

    mem::heap::init();
    serial::println(b"[NONOS] Heap initialized");

    interrupts::init_idt();
    serial::println(b"[NONOS] Full IDT loaded with handlers");

    apic::init();
    serial::println(b"[NONOS] APIC initialized");

    keyboard::init();
    mouse::init();
    serial::println(b"[NONOS] Input devices initialized");

    apic::setup_keyboard_irq();
    apic::setup_mouse_irq();
    serial::println(b"[NONOS] Keyboard and mouse IRQs enabled");

    unsafe { core::arch::asm!("sti", options(nomem, nostack)); }
    serial::println(b"[NONOS] Interrupts enabled");

    bus::pci::init();
    serial::println(b"[NONOS] PCI bus enumerated");

    if let Ok(()) = nonos_kernel::drivers::init_virtio_rng() {
        serial::println(b"[NONOS] VirtIO-RNG initialized - hardware entropy available");
    } else {
        serial::println(b"[NONOS] VirtIO-RNG not found - using software RNG only");
    }

    if handoff_ptr == 0 {
        serial::println(b"[NONOS] CRITICAL: No handoff from bootloader!");
        vga_fallback();
    }

    let handoff = match unsafe { init_handoff(handoff_ptr) } {
        Ok(h) => {
            serial::println(b"[NONOS] Boot handoff validated");
            h
        }
        Err(e) => {
            serial::println(b"[NONOS] CRITICAL: Handoff validation failed!");
            serial::print(b"[NONOS] Error: ");
            serial::println(e.as_str().as_bytes());
            vga_fallback();
        }
    };

    log_security_status(handoff);

    if handoff.fb.ptr != 0 {
        serial::print(b"[NONOS] Display: ");
        serial::print_dec(handoff.fb.width as u64);
        serial::print(b"x");
        serial::print_dec(handoff.fb.height as u64);
        serial::println(b"");

        framebuffer::init(
            handoff.fb.ptr,
            handoff.fb.width,
            handoff.fb.height,
            handoff.fb.stride,
        );
        serial::println(b"[NONOS] Framebuffer initialized");

        if framebuffer::init_double_buffer() {
            serial::println(b"[NONOS] Double buffering enabled");
        } else {
            serial::println(b"[NONOS] Double buffering failed - using direct rendering");
        }

        nonos_kernel::input::set_screen_bounds_unified(handoff.fb.width, handoff.fb.height);

        serial::println(b"[NONOS] Scanning for I2C HID devices...");
        let i2c_hid_count = nonos_kernel::input::i2c_hid::init();
        if i2c_hid_count > 0 {
            serial::println(b"[NONOS] I2C HID touchpad found!");
        } else {
            serial::println(b"[NONOS] No I2C HID devices found");
        }

        nonos_kernel::input::usb_hid::init();
        serial::println(b"[NONOS] USB HID initialized");

        clock::init(handoff.timing.tsc_hz, handoff.timing.unix_epoch_ms);
        serial::println(b"[NONOS] Clock initialized");

        storage::usb_msc::init();
        storage::fat32::init();
        serial::println(b"[NONOS] Storage initialized");

        serial::println(b"[VFS] Starting VFS init...");
        nonos_kernel::fs::vfs::init_vfs();
        serial::println(b"[VFS] VFS core initialized");
        let _ = nonos_kernel::fs::cryptofs::init_cryptofs(1024 * 1024, 4096);
        serial::println(b"[VFS] CryptoFS initialized");
        let _ = nonos_kernel::fs::ramfs::init_nonos_filesystem();
        serial::println(b"[VFS] RamFS initialized");
        nonos_kernel::fs::cache::init_all_caches();
        serial::println(b"[NONOS] VFS initialized");

        nonos_kernel::sys::settings::init();
        nonos_kernel::sys::settings::init_hostname();
        serial::println(b"[NONOS] Settings initialized");

        if storage::fat32::fs_count() > 0 {
            if nonos_kernel::sys::settings::load_from_disk() {
                serial::println(b"[NONOS] Settings loaded from disk");
            }
            if nonos_kernel::sys::settings::network::load_from_disk() {
                serial::println(b"[NONOS] Network settings loaded from disk");
            }
        }
        nonos_kernel::sys::settings::network::init();

        init_network();

        nonos_kernel::graphics::backgrounds::init_wallpaper_system();

        serial::println(b"[NONOS] Starting desktop...");
        run_desktop();
    } else {
        serial::println(b"[NONOS] No framebuffer - VGA fallback");
        vga_fallback();
    }
}

fn init_network() {
    serial::println(b"[NET] Initializing network...");

    nonos_kernel::network::init_network_stack();
    serial::println(b"[NET] Network stack initialized");

    serial::println(b"[NET] Initializing USB...");
    match nonos_kernel::drivers::xhci::init_xhci() {
        Ok(_) => {
            serial::println(b"[NET] xHCI USB controller ready");
            match nonos_kernel::drivers::usb::init_usb() {
                Ok(_) => {
                    serial::println(b"[NET] USB subsystem initialized");
                    if nonos_kernel::drivers::usb::rtl8152::is_connected() {
                        serial::println(b"[NET] USB Ethernet adapter detected!");
                        return;
                    }
                    if nonos_kernel::drivers::usb::cdc_eth::is_connected() {
                        serial::println(b"[NET] CDC Ethernet adapter detected!");
                        return;
                    }
                }
                Err(e) => {
                    serial::print(b"[NET] USB init: ");
                    serial::println(e.as_bytes());
                }
            }
        }
        Err(e) => {
            serial::print(b"[NET] xHCI: ");
            serial::println(e.as_bytes());
        }
    }

    let mut network_ready = false;
    let mut is_qemu = false;

    if nonos_kernel::network::stack::is_network_available() {
        serial::println(b"[NET] USB Ethernet active");
        network_ready = true;
    }

    if !network_ready {
        if let Ok(()) = nonos_kernel::drivers::init_virtio_net() {
            serial::println(b"[NET] VirtIO-net driver initialized");
            nonos_kernel::drivers::virtio_net::interface::register_with_smoltcp();
            serial::println(b"[NET] VirtIO-net registered with stack");
            network_ready = true;
            is_qemu = true;
        }
    }

    if !network_ready {
        if let Ok(()) = nonos_kernel::drivers::network::e1000::init() {
            serial::println(b"[NET] e1000 Ethernet driver initialized");
            if let Some(dev) = nonos_kernel::drivers::network::e1000::get_driver() {
                nonos_kernel::network::register_device(dev);
                serial::println(b"[NET] e1000 registered with stack");
                network_ready = true;
                is_qemu = true;
            }
        }
    }

    if !network_ready {
        if nonos_kernel::drivers::rtl8168_is_present() {
            serial::println(b"[NET] RTL8168 Gigabit Ethernet detected");
            nonos_kernel::drivers::rtl8168::register_with_network_stack();
            serial::println(b"[NET] RTL8168 registered with stack");
            network_ready = true;
        }
    }

    if !network_ready {
        if nonos_kernel::drivers::rtl8139_is_present() {
            serial::println(b"[NET] RTL8139 Fast Ethernet detected");
            nonos_kernel::drivers::rtl8139::register_with_network_stack();
            serial::println(b"[NET] RTL8139 registered with stack");
            network_ready = true;
        }
    }

    if network_ready {
        if let Some(stack) = nonos_kernel::network::get_network_stack() {
            if is_qemu {
                serial::println(b"[NET] QEMU mode: Using static IP 10.0.2.15...");
                stack.set_ipv4_config([10, 0, 2, 15], 24, Some([10, 0, 2, 2]));
                stack.set_default_dns_v4([10, 0, 2, 3]);
                nonos_kernel::network::stack::set_network_connected(true);
                serial::println(b"[NET] Static IP configured");
            } else {
                serial::println(b"[NET] Real hardware: Requesting DHCP lease...");
                match stack.request_dhcp() {
                    Ok(_lease) => {
                        serial::println(b"[NET] DHCP lease acquired!");
                        nonos_kernel::network::stack::set_network_connected(true);
                    }
                    Err(e) => {
                        serial::print(b"[NET] DHCP failed: ");
                        serial::println(e.as_bytes());
                        serial::println(b"[NET] Network available but not configured");
                    }
                }
            }
        }
        serial::println(b"[NET] Ethernet ready");
    } else {
        serial::println(b"[NET] No Ethernet detected");
    }

    serial::println(b"[NET] Initializing WiFi...");
    let wifi_count = nonos_kernel::drivers::wifi::init();
    if wifi_count > 0 {
        serial::println(b"[NET] WiFi adapter(s) found");
        serial::println(b"[NET] Loading WiFi firmware...");
        match nonos_kernel::drivers::wifi::try_load_firmware() {
            Ok(()) => {
                serial::println(b"[NET] WiFi firmware loaded successfully");
            }
            Err(_) => {
                serial::println(b"[NET] WiFi firmware not found on USB - place IWLWIFI.BIN or RTW88FW.BIN on FAT32 USB drive");
            }
        }
        nonos_kernel::drivers::wifi::print_status();
    } else {
        serial::println(b"[NET] No WiFi adapter found");
    }

    if !network_ready && wifi_count == 0 {
        serial::println(b"[NET] Warning: No network interfaces available");
    }
}

fn log_security_status(handoff: &BootHandoffV1) {
    serial::println(b"[NONOS] === Security Status ===");

    if handoff.meas.kernel_sig_ok != 0 {
        serial::println(b"[NONOS] Kernel signature: VERIFIED");
    } else {
        serial::println(b"[NONOS] Kernel signature: NOT VERIFIED");
    }

    if handoff.meas.secure_boot != 0 {
        serial::println(b"[NONOS] Secure Boot: ENABLED");
    } else {
        serial::println(b"[NONOS] Secure Boot: DISABLED");
    }

    let has_entropy = handoff.rng.seed32.iter().any(|&b| b != 0);
    serial::print(b"[NONOS] Bootloader entropy[0..8]: ");
    for i in 0..8 {
        serial::print_hex(handoff.rng.seed32[i] as u64);
        serial::print(b" ");
    }
    serial::println(b"");

    if has_entropy {
        serial::println(b"[NONOS] RNG seed: AVAILABLE - applying...");
        if let Err(_) = nonos_kernel::crypto::rng::seed_from_bootloader(&handoff.rng.seed32) {
            serial::println(b"[NONOS] RNG seed: FAILED TO APPLY");
        } else {
            serial::println(b"[NONOS] RNG seed: APPLIED SUCCESSFULLY");
        }
    } else {
        serial::println(b"[NONOS] RNG seed: ALL ZEROS - bootloader entropy missing!");
    }

    serial::println(b"[NONOS] ========================");
}

fn run_desktop() -> ! {
    desktop::draw_all();
    framebuffer::swap_buffers();
    serial::println(b"[NONOS] Desktop drawn");
    serial::println(b"[NONOS] Desktop ready");

    let (mut old_mx, mut old_my) = nonos_kernel::input::mouse_position_unified();
    framebuffer::double_buffer::disable();
    cursor::draw(old_mx, old_my);
    framebuffer::double_buffer::enable();

    let mut last_clock_update = nonos_kernel::sys::clock::unix_ms();

    serial::println(b"[NONOS] Entering main loop");

    let mut loop_counter: u64 = 0;
    loop {
        loop_counter += 1;

        if loop_counter % 1_000_000 == 0 {
            serial::print(b".");
        }

        if let Some(ch) = nonos_kernel::input::poll_keyboard_unified() {
            serial::print(b"[KEY] ch=");
            serial::print_dec(ch as u64);
            serial::print(b" focused=");
            serial::print_dec(if window::is_text_input_focused() { 1 } else { 0 });
            serial::println(b"");

            if window::handle_shortcut(ch) {
                serial::println(b"[KEY] Shortcut handled");
                unsafe { NEEDS_REDRAW = true; }
            } else if window::is_text_input_focused() {
                serial::print(b"[KEY->WIN] ");
                serial::print(&[ch]);
                serial::println(b"");
                window::handle_key(ch);
                unsafe { NEEDS_REDRAW = true; }
            }
        }

        if nonos_kernel::input::keyboard::is_alt_pressed() {
            if let Some(evt) = nonos_kernel::input::poll_special_key() {
                use nonos_kernel::input::KeyEvent;
                match evt {
                    KeyEvent::Left => {
                        window::snap_left();
                        unsafe { NEEDS_REDRAW = true; }
                    }
                    KeyEvent::Right => {
                        window::snap_right();
                        unsafe { NEEDS_REDRAW = true; }
                    }
                    KeyEvent::Up => {
                        window::snap_top();
                        unsafe { NEEDS_REDRAW = true; }
                    }
                    KeyEvent::Down => {
                        window::unsnap_focused();
                        unsafe { NEEDS_REDRAW = true; }
                    }
                    _ => {}
                }
            }
        }

        if window::is_editor_focused() {
            if let Some(evt) = nonos_kernel::input::poll_special_key() {
                use nonos_kernel::input::KeyEvent;
                use nonos_kernel::graphics::window::text_editor::{SpecialKey, editor_special_key};
                let special = match evt {
                    KeyEvent::Up => Some(SpecialKey::Up),
                    KeyEvent::Down => Some(SpecialKey::Down),
                    KeyEvent::Left => Some(SpecialKey::Left),
                    KeyEvent::Right => Some(SpecialKey::Right),
                    KeyEvent::Home => Some(SpecialKey::Home),
                    KeyEvent::End => Some(SpecialKey::End),
                    KeyEvent::PageUp => Some(SpecialKey::PageUp),
                    KeyEvent::PageDown => Some(SpecialKey::PageDown),
                    KeyEvent::Delete => Some(SpecialKey::Delete),
                    _ => None,
                };
                if let Some(key) = special {
                    editor_special_key(key);
                    unsafe { NEEDS_REDRAW = true; }
                }
            }
        }

        if window::is_browser_focused() {
            if let Some(evt) = nonos_kernel::input::poll_special_key() {
                use nonos_kernel::input::KeyEvent;
                use nonos_kernel::graphics::window::text_editor::SpecialKey;
                let special = match evt {
                    KeyEvent::Up => Some(SpecialKey::Up),
                    KeyEvent::Down => Some(SpecialKey::Down),
                    KeyEvent::Left => Some(SpecialKey::Left),
                    KeyEvent::Right => Some(SpecialKey::Right),
                    KeyEvent::Home => Some(SpecialKey::Home),
                    KeyEvent::End => Some(SpecialKey::End),
                    KeyEvent::PageUp => Some(SpecialKey::PageUp),
                    KeyEvent::PageDown => Some(SpecialKey::PageDown),
                    KeyEvent::Delete => Some(SpecialKey::Delete),
                    _ => None,
                };
                if let Some(key) = special {
                    window::browser_special_key(key);
                    unsafe { NEEDS_REDRAW = true; }
                }
            }
        }

        if window::is_file_manager_focused() {
            if let Some(evt) = nonos_kernel::input::poll_special_key() {
                use nonos_kernel::input::KeyEvent;
                let scancode = match evt {
                    KeyEvent::Backspace => Some(0x0E),
                    KeyEvent::Enter => Some(0x1C),
                    KeyEvent::Escape => Some(0x01),
                    _ => None,
                };
                if let Some(sc) = scancode {
                    if window::file_manager_special_key(sc) {
                        unsafe { NEEDS_REDRAW = true; }
                    }
                }
            }
        }

        let scroll_delta = nonos_kernel::input::mouse::take_scroll_delta();
        if scroll_delta != 0 {
            let focused = window::FOCUSED_WINDOW.load(core::sync::atomic::Ordering::Relaxed);
            if focused < window::MAX_WINDOWS {
                window::scroll_window_by(focused, 0, scroll_delta * 3);
                unsafe { NEEDS_REDRAW = true; }
            }
        }

        if nonos_kernel::input::poll_mouse_unified() {
            let (mx, my) = nonos_kernel::input::mouse_position_unified();
            let left_btn = nonos_kernel::input::left_button_pressed();
            let right_btn = nonos_kernel::input::right_button_pressed();

            if nonos_kernel::graphics::window::context_menu::is_visible() {
                nonos_kernel::graphics::window::context_menu::update_hover(mx, my);
            }

            unsafe {
                if left_btn && !PREV_LEFT_BUTTON {
                    if nonos_kernel::graphics::window::context_menu::is_visible() {
                        if let Some(action) = nonos_kernel::graphics::window::context_menu::handle_click(mx, my) {
                            handle_context_menu_action(action);
                        }
                        NEEDS_REDRAW = true;
                    } else if !window::handle_click(mx, my, true) {
                        if desktop::handle_menu_bar_click(mx, my) {
                            NEEDS_REDRAW = true;
                        } else if desktop::handle_sidebar_click(mx, my) {
                            NEEDS_REDRAW = true;
                        } else if desktop::handle_dock_click(mx, my) {
                            NEEDS_REDRAW = true;
                        }
                    } else {
                        NEEDS_REDRAW = true;
                    }
                } else if !left_btn && PREV_LEFT_BUTTON {
                    window::handle_click(mx, my, false);
                }
                PREV_LEFT_BUTTON = left_btn;

                if right_btn && !PREV_RIGHT_BUTTON {
                    nonos_kernel::graphics::window::context_menu::hide();
                    use nonos_kernel::graphics::window::context_menu::{ContextMenuType, show as show_menu};
                    let menu_type = get_context_menu_type(mx, my);
                    if menu_type != ContextMenuType::None {
                        show_menu(mx, my, menu_type);
                        NEEDS_REDRAW = true;
                    }
                }
                PREV_RIGHT_BUTTON = right_btn;
            }

            let is_dragging = window::is_dragging();
            if is_dragging {
                window::handle_drag(mx, my);
                unsafe { WAS_DRAGGING = true; }
            } else if unsafe { WAS_DRAGGING } {
                unsafe {
                    NEEDS_REDRAW = true;
                    WAS_DRAGGING = false;
                }
            }

            if mx != old_mx || my != old_my {
                unsafe {
                    if NEEDS_REDRAW || is_dragging {
                        framebuffer::double_buffer::disable();
                        cursor::erase();
                        framebuffer::double_buffer::enable();
                        desktop::redraw_background();
                        window::draw_all();
                        nonos_kernel::graphics::window::context_menu::draw();
                        cursor::draw(mx, my);
                        framebuffer::swap_buffers();
                        NEEDS_REDRAW = false;
                    } else {
                        framebuffer::double_buffer::disable();
                        cursor::erase();
                        cursor::draw(mx, my);
                        framebuffer::double_buffer::enable();
                    }
                }
                old_mx = mx;
                old_my = my;
            }
        }

        nonos_kernel::network::poll_network();

        if nonos_kernel::graphics::window::browser::poll_fetch() {
            unsafe { NEEDS_REDRAW = true; }
        }

        if nonos_kernel::graphics::window::settings::take_background_changed() {
            unsafe { NEEDS_REDRAW = true; }
        }

        unsafe {
            if NEEDS_REDRAW {
                framebuffer::double_buffer::disable();
                cursor::erase();
                framebuffer::double_buffer::enable();
                desktop::redraw_background();
                window::draw_all();
                nonos_kernel::graphics::window::context_menu::draw();
                cursor::draw(old_mx, old_my);
                framebuffer::swap_buffers();
                NEEDS_REDRAW = false;
            }
        }

        let now_ms = nonos_kernel::sys::clock::unix_ms();
        if now_ms >= last_clock_update + 1000 {
            last_clock_update = now_ms;
            desktop::update_clock();
        }

        for _ in 0..100 {
            unsafe { asm!("pause", options(nomem, nostack)); }
        }
    }
}

fn get_context_menu_type(mx: i32, my: i32) -> nonos_kernel::graphics::window::context_menu::ContextMenuType {
    use nonos_kernel::graphics::window::context_menu::ContextMenuType;
    use nonos_kernel::graphics::window::{WINDOWS, FOCUSED_WINDOW, MAX_WINDOWS, window_type_from_u32, WindowType};
    use core::sync::atomic::Ordering;

    let focused = FOCUSED_WINDOW.load(Ordering::Relaxed);
    if focused < MAX_WINDOWS && WINDOWS[focused].active.load(Ordering::Relaxed) {
        let wx = WINDOWS[focused].x.load(Ordering::Relaxed);
        let wy = WINDOWS[focused].y.load(Ordering::Relaxed);
        let ww = WINDOWS[focused].width.load(Ordering::Relaxed) as i32;
        let wh = WINDOWS[focused].height.load(Ordering::Relaxed) as i32;

        if mx >= wx && mx < wx + ww && my >= wy && my < wy + wh {
            let wtype = window_type_from_u32(WINDOWS[focused].window_type.load(Ordering::Relaxed));
            return match wtype {
                WindowType::FileManager => ContextMenuType::FileManager,
                WindowType::TextEditor => ContextMenuType::TextEditor,
                _ => ContextMenuType::Window,
            };
        }
    }

    for i in (0..MAX_WINDOWS).rev() {
        if WINDOWS[i].active.load(Ordering::Relaxed) && !WINDOWS[i].minimized.load(Ordering::Relaxed) {
            let wx = WINDOWS[i].x.load(Ordering::Relaxed);
            let wy = WINDOWS[i].y.load(Ordering::Relaxed);
            let ww = WINDOWS[i].width.load(Ordering::Relaxed) as i32;
            let wh = WINDOWS[i].height.load(Ordering::Relaxed) as i32;

            if mx >= wx && mx < wx + ww && my >= wy && my < wy + wh {
                return ContextMenuType::Window;
            }
        }
    }

    ContextMenuType::Desktop
}

fn handle_context_menu_action(action: u8) {
    use nonos_kernel::graphics::window::context_menu::actions::*;
    use nonos_kernel::graphics::window::{self, WindowType};

    match action {
        DESKTOP_REFRESH => {
            unsafe { NEEDS_REDRAW = true; }
        }
        DESKTOP_SETTINGS => {
            window::open(WindowType::Settings);
        }
        DESKTOP_ABOUT => {
            window::open(WindowType::About);
        }
        FM_OPEN => {
            window::fm_open_selected();
        }
        FM_COPY => {
            let _ = window::fm_copy_selected();
        }
        FM_CUT => {
            let _ = window::fm_cut_selected();
        }
        FM_PASTE => {
            let _ = window::fm_paste();
        }
        FM_DELETE => {
            let _ = window::fm_delete_selected();
        }
        FM_NEW_FOLDER => {
            let _ = window::fm_create_folder("NewFolder");
        }
        EDIT_CUT => {
            window::text_editor::editor_cut();
        }
        EDIT_COPY => {
            window::text_editor::editor_copy();
        }
        EDIT_PASTE => {
            window::text_editor::editor_paste();
        }
        EDIT_SELECT_ALL => {
            window::text_editor::editor_select_all();
        }
        WIN_MINIMIZE => {
            use core::sync::atomic::Ordering;
            let focused = window::FOCUSED_WINDOW.load(Ordering::Relaxed);
            if focused < window::MAX_WINDOWS {
                window::minimize(focused);
            }
        }
        WIN_MAXIMIZE => {
            use core::sync::atomic::Ordering;
            let focused = window::FOCUSED_WINDOW.load(Ordering::Relaxed);
            if focused < window::MAX_WINDOWS {
                window::maximize(focused);
            }
        }
        WIN_CLOSE => {
            use core::sync::atomic::Ordering;
            let focused = window::FOCUSED_WINDOW.load(Ordering::Relaxed);
            if focused < window::MAX_WINDOWS {
                window::close(focused);
            }
        }
        _ => {}
    }

    unsafe { NEEDS_REDRAW = true; }
}

fn vga_fallback() -> ! {
    const VGA_BUFFER: *mut u8 = 0xB8000 as *mut u8;

    unsafe {
        for i in 0..(80 * 25) {
            *VGA_BUFFER.add(i * 2) = b' ';
            *VGA_BUFFER.add(i * 2 + 1) = 0x1F;
        }

        let msg = b"NONOS v1.0.0 - No framebuffer available";
        for (i, &ch) in msg.iter().enumerate() {
            *VGA_BUFFER.add(i * 2) = ch;
        }
    }

    loop {
        unsafe { asm!("hlt"); }
    }
}

#[no_mangle]
pub unsafe extern "C" fn memcpy(d: *mut u8, s: *const u8, n: usize) -> *mut u8 {
    unsafe {
        let mut i = 0;
        while i < n {
            *d.add(i) = *s.add(i);
            i += 1;
        }
        d
    }
}

#[no_mangle]
pub unsafe extern "C" fn memset(d: *mut u8, c: i32, n: usize) -> *mut u8 {
    unsafe {
        let mut i = 0;
        while i < n {
            *d.add(i) = c as u8;
            i += 1;
        }
        d
    }
}

#[no_mangle]
pub unsafe extern "C" fn memcmp(a: *const u8, b: *const u8, n: usize) -> i32 {
    unsafe {
        let mut i = 0;
        while i < n {
            if *a.add(i) != *b.add(i) {
                return (*a.add(i) as i32) - (*b.add(i) as i32);
            }
            i += 1;
        }
        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn memmove(d: *mut u8, s: *const u8, n: usize) -> *mut u8 {
    unsafe {
        if (d as usize) < (s as usize) {
            memcpy(d, s, n)
        } else {
            let mut i = n;
            while i > 0 {
                i -= 1;
                *d.add(i) = *s.add(i);
            }
            d
        }
    }
}
