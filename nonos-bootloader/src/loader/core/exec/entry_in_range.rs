// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

// Range-check the ELF entry point against the loaded image.
//
// Upper-half kernels: entry is a virt address, must lie inside the
// declared virt window `[virt_min, virt_min + total_bytes)`.
//
// Legacy low-half ET_EXEC: entry coincides with phys, must lie
// inside the allocated phys range `[phys_base, phys_base + total)`.
pub fn entry_in_range(
    entry: usize,
    upper_half: bool,
    virt_min: u64,
    phys_base: u64,
    total_bytes: usize,
) -> bool {
    if upper_half {
        let base = virt_min as usize;
        entry >= base && entry < base + total_bytes
    } else {
        let base = phys_base as usize;
        entry >= base && entry < base + total_bytes
    }
}
