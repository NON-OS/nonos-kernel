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

use crate::memory::paging;
use x86_64::VirtAddr;

pub fn read_bytes(start: usize, size: usize) -> Result<&'static [u8], &'static str> {
    let va = VirtAddr::new(start as u64);
    if !paging::is_mapped(va) {
        return Err("Memory not mapped");
    }
    let end_va = VirtAddr::new((start + size) as u64);
    if !paging::is_mapped(end_va) {
        return Err("End of range not mapped");
    }
    unsafe { Ok(core::slice::from_raw_parts(start as *const u8, size)) }
}
