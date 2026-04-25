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

extern crate alloc as alloc_crate;

use alloc_crate::collections::BTreeSet;
use core::sync::atomic::{AtomicI32, Ordering};
use spin::Mutex;

pub const PKEY_DISABLE_ACCESS: u32 = 0x1;
pub const PKEY_DISABLE_WRITE: u32 = 0x2;
pub const PKEY_MAX: i32 = 16;

static ALLOCATED_PKEYS: Mutex<BTreeSet<i32>> = Mutex::new(BTreeSet::new());
static NEXT_PKEY: AtomicI32 = AtomicI32::new(1);

#[derive(Debug, Clone, Copy)]
pub struct ProtectionKey {
    pub key: i32,
    pub access_rights: u32,
}

impl ProtectionKey {
    pub fn allocate(init_val: u32) -> Result<i32, i32> {
        let mut allocated = ALLOCATED_PKEYS.lock();
        let pkey = NEXT_PKEY.fetch_add(1, Ordering::SeqCst);
        if pkey >= PKEY_MAX {
            return Err(28);
        }
        allocated.insert(pkey);
        let _ = init_val;
        Ok(pkey)
    }

    pub fn free(pkey: i32) -> Result<(), i32> {
        if pkey <= 0 || pkey >= PKEY_MAX {
            return Err(22);
        }
        let mut allocated = ALLOCATED_PKEYS.lock();
        if allocated.remove(&pkey) {
            Ok(())
        } else {
            Err(22)
        }
    }

    pub fn is_valid(pkey: i32) -> bool {
        pkey >= 0 && pkey < PKEY_MAX && ALLOCATED_PKEYS.lock().contains(&pkey)
    }
}
