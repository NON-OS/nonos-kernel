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

use crate::services::{ServiceServer, CAP_VFS};
use super::dispatch::handle_request;

pub fn run_vfs_service() -> ! {
    crate::sys::serial::println(b"[VFS] run_vfs_service entered");
    crate::sys::serial::println(b"[VFS] VFS service starting");

    crate::sys::serial::println(b"[VFS] calling new()");
    let server = match ServiceServer::new("vfs", CAP_VFS) {
        Ok(s) => {
            crate::sys::serial::println(b"[VFS] new() ok");
            s
        }
        Err(_) => {
            crate::sys::serial::println(b"[VFS] Failed to create server");
            loop { crate::sched::yield_now(); }
        }
    };

    crate::sys::serial::println(b"[VFS] after match");
    crate::sys::serial::println(b"[VFS] VFS server ready");

    loop {
        server.poll_once(&mut handle_request);
        crate::sched::yield_now();
    }
}
