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

use super::dispatch::handle_request;

pub fn run_vfs_service() -> ! {
    init_ramfs_first();
    crate::services::registry::register_endpoint_simple("vfs", 1000, 2);
    crate::sys::boot_log::ok("VFS", "Service ready");
    init_storage_deferred();
    loop {
        handle_vfs_requests();
        crate::sched::yield_now();
    }
}

fn init_ramfs_first() {
    crate::fs::vfs::init_vfs();
    let _ = crate::fs::ramfs::init_nonos_filesystem();
    crate::fs::cache::init_all_caches();
}

fn init_storage_deferred() {
    crate::sched::yield_now();
    crate::storage::usb_msc::init();
    crate::sched::yield_now();
    crate::storage::fat32::init();
    crate::sched::yield_now();
    let _ = crate::fs::cryptofs::init_cryptofs(1024 * 1024, 4096);
    load_persistent_settings();
}

fn load_persistent_settings() {
    if crate::storage::fat32::fs_count() > 0 {
        let _ = crate::sys::settings::load_from_disk();
    }
}

fn handle_vfs_requests() {
    if let Some(msg) = crate::ipc::nonos_inbox::try_dequeue("vfs") {
        if let Some(req) = crate::services::server::parsing::parse_request(&msg.data) {
            let resp = handle_request(req);
            let data = crate::services::server::parsing::encode_response(&resp);
            if let Ok(reply) = crate::ipc::nonos_channel::IpcMessage::new("vfs", &msg.from, &data) {
                let _ = crate::ipc::nonos_inbox::try_enqueue(&msg.from, reply);
            }
        }
    }
}
