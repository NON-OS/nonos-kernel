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

extern crate alloc;

use alloc::vec::Vec;
use spin::Mutex;

use super::types::SurfaceHandle;

#[derive(Clone, Copy)]
struct AttachRecord {
    pid: u32,
    handle: SurfaceHandle,
    base_va: u64,
    byte_len: u64,
}

static ATTACHES: Mutex<Vec<AttachRecord>> = Mutex::new(Vec::new());

pub fn record(pid: u32, handle: SurfaceHandle, base_va: u64, byte_len: u64) {
    let mut v = ATTACHES.lock();
    for rec in v.iter_mut() {
        if rec.pid == pid && rec.handle == handle {
            rec.base_va = base_va;
            rec.byte_len = byte_len;
            return;
        }
    }
    v.push(AttachRecord { pid, handle, base_va, byte_len });
}

pub fn lookup(pid: u32, handle: SurfaceHandle) -> Option<(u64, u64)> {
    let v = ATTACHES.lock();
    v.iter()
        .find(|r| r.pid == pid && r.handle == handle)
        .map(|r| (r.base_va, r.byte_len))
}

pub fn forget(pid: u32, handle: SurfaceHandle) {
    let mut v = ATTACHES.lock();
    v.retain(|r| !(r.pid == pid && r.handle == handle));
}

pub fn forget_pid(pid: u32) {
    let mut v = ATTACHES.lock();
    v.retain(|r| r.pid != pid);
}
