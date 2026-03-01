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

use super::cpuid;

#[inline(always)]
pub fn mds_clear() {
    if cpuid::has_md_clear() {
        // SAFETY: VERW instruction with memory operand clears MDS-affected buffers.
        unsafe {
            let dummy: u16 = 0;
            core::arch::asm!(
                "verw [{0}]",
                in(reg) &dummy,
                options(nomem, nostack, preserves_flags)
            );
        }
    }
}
