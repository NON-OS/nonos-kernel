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

mod pty;

pub use pty::*;

use crate::fs::devfs::major_minor::UNIX98_PTY_SLAVE_MAJOR;
use crate::fs::devfs::types::DeviceNode;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use spin::Mutex;

static NEXT_PTY: AtomicU32 = AtomicU32::new(0);
static ALLOCATED_PTYS: Mutex<Vec<u32>> = Mutex::new(Vec::new());
static MAX_PTYS: u32 = 4096;

pub fn init_pts() {
    NEXT_PTY.store(0, Ordering::SeqCst);
}

pub fn allocate_pty() -> Result<u32, i32> {
    let mut allocated = ALLOCATED_PTYS.lock();
    if allocated.len() >= MAX_PTYS as usize {
        return Err(-23);
    }
    let num = NEXT_PTY.fetch_add(1, Ordering::SeqCst);
    allocated.push(num);
    crate::tty::pty::create_pair(num)?;
    Ok(num)
}

pub fn deallocate_pty(num: u32) {
    let mut allocated = ALLOCATED_PTYS.lock();
    allocated.retain(|&n| n != num);
    crate::tty::pty::destroy_pair(num);
}

pub fn get_pty_count() -> usize {
    ALLOCATED_PTYS.lock().len()
}

pub fn list_ptys() -> Vec<DeviceNode> {
    ALLOCATED_PTYS
        .lock()
        .iter()
        .map(|&num| {
            DeviceNode::char_device(
                &alloc::format!("{}", num),
                UNIX98_PTY_SLAVE_MAJOR,
                num,
                0o620,
                100 + num as u64 + 1,
            )
        })
        .collect()
}
