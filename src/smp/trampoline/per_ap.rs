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

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PerApBootContext {
    pub pml4_phys: u64,
    pub stack_top: u64,
    pub entry_ptr: u64,
    pub cpu_id: u32,
}

impl PerApBootContext {
    pub const fn new(pml4_phys: u64, stack_top: u64, entry_ptr: u64, cpu_id: u32) -> Self {
        Self { pml4_phys, stack_top, entry_ptr, cpu_id }
    }
}
