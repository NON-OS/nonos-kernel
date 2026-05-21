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

use super::reload_cr3::reload_cr3;
use super::walk_pml4_entry::walk_pml4_entry;
use crate::memory::encryption::cbit_validate::validate_c_bit_position;
use crate::memory::encryption::error::MemEncryptionResult;
use crate::memory::paging::tlb::get_cr3;

pub unsafe fn apply_cbit_to_kernel_mappings(c_bit_position: u8) -> MemEncryptionResult<u64> {
    validate_c_bit_position(c_bit_position)?;
    let c_bit_mask = 1u64 << c_bit_position;
    let cr3 = get_cr3().as_u64();
    let mut touched = 0u64;
    touched += walk_pml4_entry(cr3, 256, c_bit_mask);
    touched += walk_pml4_entry(cr3, 511, c_bit_mask);
    reload_cr3();
    Ok(touched)
}
