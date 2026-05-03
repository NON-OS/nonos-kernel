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

use super::super::setup_menu;
use super::components::{init_desktop, init_services, init_storage_and_fs};
use crate::boot::handoff::BootHandoffV1;
use crate::display::{register_framebuffer, FramebufferInfo};
use crate::graphics::framebuffer;
use crate::input;
use crate::sys::clock;

pub fn init_graphics(handoff: &BootHandoffV1) {
    init_framebuffer(handoff);
    init_input_devices(handoff);
    init_storage_and_fs();
    init_services();

    // Run setup menu on first boot
    if setup_menu::needs_setup() {
        crate::sys::serial::println(b"[NONOS] Running first-time setup");
        let config = setup_menu::run_setup_menu();
        setup_menu::apply_config(&config);
    }

    init_desktop();
}

fn init_framebuffer(handoff: &BootHandoffV1) {
    let fb_phys = crate::memory::PhysAddr::new(handoff.fb.ptr);
    let fb_virt = crate::memory::mmio::map_framebuffer(fb_phys, handoff.fb.size as usize)
        .map(|va| va.as_u64())
        .unwrap_or(handoff.fb.ptr);
    let info = FramebufferInfo {
        addr: fb_virt,
        width: handoff.fb.width,
        height: handoff.fb.height,
        stride: handoff.fb.stride * 4,
        bpp: 32,
    };
    if register_framebuffer(info).is_err() {
        return;
    }
    let _ = framebuffer::init_double_buffer();
}

fn init_input_devices(handoff: &BootHandoffV1) {
    crate::sys::serial::println(b"[BOOT] init_input_devices");
    input::set_screen_bounds_unified(handoff.fb.width, handoff.fb.height);
    let _ = input::i2c_hid::init();
    input::usb_hid::init();
    crate::sys::serial::print(b"[BOOT] USB mouse_avail=");
    crate::sys::serial::print_dec(input::usb_hid::mouse_available() as u64);
    crate::sys::serial::print(b" kbd_avail=");
    crate::sys::serial::print_dec(input::usb_hid::keyboard_available() as u64);
    crate::sys::serial::println(b"");
    clock::init(handoff.timing.tsc_hz, handoff.timing.unix_epoch_ms);
}
