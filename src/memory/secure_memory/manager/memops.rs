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

use super::super::error::SecureMemoryResult;
use crate::memory::addr::VirtAddr;

pub fn zero_memory(va: VirtAddr, size: usize) -> SecureMemoryResult<()> {
    if size == 0 {
        return Ok(());
    }
    unsafe {
        core::ptr::write_bytes(va.as_mut_ptr::<u8>(), 0, size);
    }
    Ok(())
}

pub fn copy_memory(src: VirtAddr, dst: VirtAddr, size: usize) -> SecureMemoryResult<()> {
    if size == 0 {
        return Ok(());
    }
    unsafe {
        core::ptr::copy_nonoverlapping(src.as_ptr::<u8>(), dst.as_mut_ptr::<u8>(), size);
    }
    Ok(())
}
