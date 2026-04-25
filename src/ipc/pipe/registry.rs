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
use super::types::Pipe;
use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU32, Ordering};
use spin::Mutex;

pub(super) static PIPES: Mutex<BTreeMap<u32, Pipe>> = Mutex::new(BTreeMap::new());
pub(super) static NEXT_PIPE_ID: AtomicU32 = AtomicU32::new(1);
pub(super) static FD_TO_PIPE: Mutex<BTreeMap<i32, (u32, bool)>> = Mutex::new(BTreeMap::new());
static NEXT_FD: AtomicU32 = AtomicU32::new(4000);

pub(super) fn allocate_fd() -> i32 {
    NEXT_FD.fetch_add(1, Ordering::SeqCst) as i32
}
