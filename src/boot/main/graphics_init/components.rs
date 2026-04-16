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

use crate::graphics::{framebuffer, desktop, cursor};
use crate::input;
use crate::storage;
use crate::entry::network;

pub(super) fn init_storage_and_fs() {
    storage::usb_msc::init();
    storage::fat32::init();
    crate::fs::vfs::init_vfs();
    let _ = crate::fs::cryptofs::init_cryptofs(1024 * 1024, 4096);
    let _ = crate::fs::ramfs::init_nonos_filesystem();
    crate::fs::cache::init_all_caches();
}

pub(super) fn init_services() {
    crate::sys::settings::init();
    crate::sys::settings::init_hostname();
    crate::process::init_process_management();
    crate::agents::init();
    crate::sdk::init();
    network::init_network();
    let _ = crate::vault::nonos_vault::initialize_vault();
}

pub(super) fn init_desktop() {
    crate::graphics::backgrounds::init_wallpaper_system();
    crate::sys::serial::println(b"[NONOS] Loading wallpaper");
    crate::graphics::backgrounds::try_load_wallpaper();
    crate::sys::serial::println(b"[NONOS] Starting desktop");
    crate::sys::apic::setup_timer(100);
    desktop::draw_all();
    let (mx, my) = input::mouse_position_unified();
    cursor::draw(mx, my);
    framebuffer::swap_buffers();
}
