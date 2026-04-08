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

#[inline]
pub unsafe fn read_cr4() -> u64 {
    let cr4: u64;
    unsafe {
        core::arch::asm!("mov {}, cr4", out(reg) cr4);
    }
    cr4
}

#[inline]
pub unsafe fn write_cr4(value: u64) {
    unsafe {
        core::arch::asm!("mov cr4, {}", in(reg) value);
    }
}
