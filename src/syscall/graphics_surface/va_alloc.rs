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

use alloc::collections::BTreeMap;
use spin::Mutex;

const SURFACE_VA_BASE: u64 = 0x0000_5000_0000;
const SURFACE_VA_PER_PID: u64 = 0x0000_0010_0000_0000;

static PER_PID_NEXT: Mutex<BTreeMap<u32, u64>> = Mutex::new(BTreeMap::new());

pub fn allocate(pid: u32, span: u64) -> Option<u64> {
    let window_base = SURFACE_VA_BASE + (pid as u64) * SURFACE_VA_PER_PID;
    let window_end = window_base + SURFACE_VA_PER_PID;
    let mut map = PER_PID_NEXT.lock();
    let next = map.entry(pid).or_insert(window_base);
    let base = *next;
    let end = base.checked_add(span)?;
    if end > window_end {
        return None;
    }
    *next = end;
    Some(base)
}

pub fn release(pid: u32) {
    PER_PID_NEXT.lock().remove(&pid);
}
