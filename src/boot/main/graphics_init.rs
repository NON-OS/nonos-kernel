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

use crate::boot::handoff::BootHandoffV1;
use crate::graphics::{framebuffer, desktop, cursor};
use crate::sys::{serial, clock};
use crate::{storage, input};
use crate::entry::network;

pub fn init_graphics(handoff: &BootHandoffV1) {
    init_framebuffer(handoff);
    init_input_devices(handoff);
    init_storage_and_fs();
    init_services();
    init_desktop();
}

fn init_framebuffer(handoff: &BootHandoffV1) {
    serial::print(b"[NONOS] Display: ");
    serial::print_dec(handoff.fb.width as u64);
    serial::print(b"x");
    serial::print_dec(handoff.fb.height as u64);
    serial::println(b"");
    let fb_phys = crate::memory::PhysAddr::new(handoff.fb.ptr);
    let fb_virt = crate::memory::mmio::map_framebuffer(fb_phys, handoff.fb.size as usize)
        .map(|va| va.as_u64())
        .unwrap_or(handoff.fb.ptr);
    framebuffer::init(fb_virt, handoff.fb.width, handoff.fb.height, handoff.fb.stride);
    let _ = framebuffer::init_double_buffer();
    serial::println(b"[NONOS] Framebuffer ready");
}

fn init_input_devices(handoff: &BootHandoffV1) {
    input::set_screen_bounds_unified(handoff.fb.width, handoff.fb.height);
    let _ = input::i2c_hid::init();
    input::usb_hid::init();
    clock::init(handoff.timing.tsc_hz, handoff.timing.unix_epoch_ms);
    serial::println(b"[NONOS] Input ready");
}

fn init_storage_and_fs() {
    storage::usb_msc::init();
    storage::fat32::init();
    crate::fs::vfs::init_vfs();
    let _ = crate::fs::cryptofs::init_cryptofs(1024 * 1024, 4096);
    let _ = crate::fs::ramfs::init_nonos_filesystem();
    crate::fs::cache::init_all_caches();
    serial::println(b"[NONOS] Storage ready");
}

fn init_services() {
    crate::sys::settings::init();
    crate::sys::settings::init_hostname();
    crate::process::init_process_management();
    crate::agents::init();
    crate::sdk::init();
    network::init_network();
    let _ = crate::vault::nonos_vault::initialize_vault();
    serial::println(b"[NONOS] Services ready");
}

fn init_desktop() {
    crate::graphics::backgrounds::init_wallpaper_system();
    desktop::refresh_desktop_icons();
    desktop::draw_all();
    let (mx, my) = input::mouse_position_unified();
    cursor::draw(mx, my);
    framebuffer::swap_buffers();
    serial::println(b"[NONOS] Desktop ready");
}
