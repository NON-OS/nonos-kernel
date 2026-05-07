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

// Read CR3. Low 12 bits are control flags; mask them off if you
// only want the PML4 frame.
#[inline]
pub fn read_cr3() -> u64 {
    let cr3: u64;
    unsafe {
        core::arch::asm!(
            "mov %cr3, {0}",
            out(reg) cr3,
            options(att_syntax, nostack, preserves_flags)
        );
    }
    cr3
}
