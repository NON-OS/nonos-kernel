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

use crate::input;
use crate::sys::{clock, timer};
use super::components::init_desktop;
use super::super::setup_menu;

pub fn init_graphics_for_microkernel() -> bool {
    let (width, height) = crate::graphics::framebuffer::dimensions();
    if width == 0 || height == 0 {
        crate::sys::serial::println(b"[DESKTOP] No framebuffer dimensions");
        return false;
    }
    crate::sys::serial::println(b"[DESKTOP] Graphics init OK");

    let tsc_hz = timer::tsc_frequency();
    // Get real current time from RTC hardware
    let real_unix_timestamp = crate::arch::x86_64::time::rtc::read_unix_timestamp();
    let current_unix_ms = real_unix_timestamp * 1000;
    clock::init(tsc_hz, current_unix_ms);
    crate::sys::serial::println(b"[DESKTOP] Clock initialized");

    input::set_screen_bounds_unified(width, height);
    let _ = input::i2c_hid::init();
    input::usb_hid::init();
    crate::sys::serial::print(b"[BOOT] USB mouse_avail=");
    crate::sys::serial::print_dec(input::usb_hid::mouse_available() as u64);
    crate::sys::serial::print(b" kbd_avail=");
    crate::sys::serial::print_dec(input::usb_hid::keyboard_available() as u64);
    crate::sys::serial::println(b"");
    if setup_menu::needs_setup() {
        crate::sys::serial::println(b"[NONOS] Running first-time setup");
        let config = setup_menu::run_setup_menu();
        crate::sys::serial::println(b"[NONOS] Setup returned, applying config");
        setup_menu::apply_config(&config);
        crate::sys::serial::println(b"[NONOS] Config applied, starting desktop");
    }
    init_desktop();
    true
}
