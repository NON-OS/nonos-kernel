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

use crate::graphics::{framebuffer, desktop, cursor, window};
use crate::sys::clock;
use crate::entry::desktop_loop;
use crate::input;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use super::dialogs::handle_dialogs;

static ICONS_REFRESHED: AtomicBool = AtomicBool::new(false);
static WALLPAPER_LOADED: AtomicBool = AtomicBool::new(false);
static BOOT_TIME: AtomicU64 = AtomicU64::new(0);
static INPUT_DIAG_DONE: AtomicBool = AtomicBool::new(false);

pub fn run_desktop() -> ! {
    let (mut old_mx, mut old_my) = input::mouse_position_unified();
    framebuffer::double_buffer::disable();
    cursor::draw(old_mx, old_my);
    framebuffer::double_buffer::enable();
    let mut last_clock = clock::unix_ms();
    BOOT_TIME.store(last_clock, Ordering::SeqCst);
    loop {
        // One-time diagnostic: report input subsystem state
        if !INPUT_DIAG_DONE.swap(true, Ordering::SeqCst) {
            use crate::sys::serial;
            serial::print(b"[DIAG] usb_mouse=");
            serial::print_dec(input::usb_hid::mouse_available() as u64);
            serial::print(b" usb_kbd=");
            serial::print_dec(input::usb_hid::keyboard_available() as u64);
            serial::print(b" usb_init=");
            serial::print_dec(input::usb_hid::is_available() as u64);
            serial::print(b" ps2=");
            serial::print_dec(input::mouse::is_available() as u64);
            serial::println(b"");
        }
        handle_dialogs();
        desktop_loop::handle_keyboard_input();
        desktop_loop::handle_mouse_input(&mut old_mx, &mut old_my);
        // Disable interrupts while polling network to prevent deadlock:
        // the timer ISR calls network_tick() which acquires the same
        // network locks (virtio_net, iface, sockets).
        {
            use crate::arch::x86_64::idt::{are_enabled, disable, enable};
            let was = are_enabled();
            disable();
            crate::network::poll_network();
            crate::apps::ecosystem::browser::poll_navigation();
            if was { enable(); }
        }
        check_redraws();
        deferred_icon_refresh();
        deferred_wallpaper_load();
        do_redraw(&mut old_mx, &mut old_my);
        update_clock(&mut last_clock);
        crate::sched::yield_now();
    }
}

fn check_redraws() {
    if window::settings::take_background_changed() { desktop_loop::set_needs_redraw(); }
    if window::ecosystem::state::take_content_changed() { desktop_loop::set_needs_redraw(); }
}

fn deferred_icon_refresh() {
    if ICONS_REFRESHED.load(Ordering::Relaxed) { return; }
    let now = clock::unix_ms();
    let boot = BOOT_TIME.load(Ordering::Relaxed);
    if now > boot + 500 {
        desktop::refresh_desktop_icons();
        ICONS_REFRESHED.store(true, Ordering::SeqCst);
        desktop_loop::set_needs_redraw();
    }
}

fn deferred_wallpaper_load() {
    if WALLPAPER_LOADED.load(Ordering::Relaxed) { return; }
    let now = clock::unix_ms();
    let boot = BOOT_TIME.load(Ordering::Relaxed);
    if now > boot + 1000 {
        crate::graphics::backgrounds::try_load_wallpaper();
        WALLPAPER_LOADED.store(true, Ordering::SeqCst);
        desktop_loop::set_needs_redraw();
    }
}

fn do_redraw(mx: &mut i32, my: &mut i32) {
    unsafe {
        if desktop_loop::NEEDS_REDRAW {
            desktop::redraw_background();
            window::draw_all();
            window::context_menu::draw();
            cursor::draw(*mx, *my);
            framebuffer::swap_buffers();
            desktop_loop::NEEDS_REDRAW = false;
        }
    }
}

fn update_clock(last: &mut u64) {
    let now = clock::unix_ms();
    if now >= *last + 1000 {
        *last = now;
        desktop::update_clock();
        desktop_loop::set_needs_redraw();
    }
}
