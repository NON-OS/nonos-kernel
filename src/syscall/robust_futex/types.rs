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

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct RobustListHead {
    pub list: u64,
    pub futex_offset: i64,
    pub list_op_pending: u64,
}

static ROBUST_LISTS: Mutex<BTreeMap<u64, (u64, usize)>> = Mutex::new(BTreeMap::new());

impl RobustListHead {
    pub const SIZE: usize = core::mem::size_of::<Self>();

    pub fn set(pid: u64, head: u64, len: usize) -> Result<(), i32> {
        if len != Self::SIZE {
            return Err(22);
        }
        ROBUST_LISTS.lock().insert(pid, (head, len));
        Ok(())
    }

    pub fn get(pid: u64) -> Option<(u64, usize)> {
        ROBUST_LISTS.lock().get(&pid).copied()
    }

    pub fn remove(pid: u64) {
        ROBUST_LISTS.lock().remove(&pid);
    }
}
