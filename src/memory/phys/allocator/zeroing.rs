// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use super::super::constants::{PAGE_SIZE, PAGE_SIZE_U64};
use super::super::types::Frame;
use crate::memory::layout;
use core::ptr;

pub fn zero_frame(frame: Frame) {
    let pa = frame.addr();
    let dm_base = layout::DIRECTMAP_BASE;
    let dm_size = layout::DIRECTMAP_SIZE;
    if pa >= dm_size {
        return;
    }
    let va = dm_base.wrapping_add(pa);
    if va < dm_base {
        return;
    }
    if va.wrapping_add(PAGE_SIZE_U64) > dm_base.wrapping_add(dm_size) {
        return;
    }
    unsafe {
        ptr::write_bytes(va as *mut u8, 0, PAGE_SIZE);
    }
}
