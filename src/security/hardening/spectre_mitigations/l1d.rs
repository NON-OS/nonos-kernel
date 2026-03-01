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
use super::msr::wrmsr;
use super::constants::{MSR_IA32_FLUSH_CMD, FLUSH_CMD_L1D};

#[inline(always)]
pub fn l1d_flush() {
    if cpuid::has_l1d_flush() {
        // SAFETY: L1D flush MSR write is valid when L1D_FLUSH feature is supported.
        unsafe { wrmsr(MSR_IA32_FLUSH_CMD, FLUSH_CMD_L1D); }
    } else {
        l1d_flush_software();
    }
}

#[inline(never)]
fn l1d_flush_software() {
    const L1D_SIZE: usize = 32 * 1024;
    static FLUSH_AREA: [u8; L1D_SIZE] = [0; L1D_SIZE];

    let mut sum: u64 = 0;
    for i in (0..L1D_SIZE).step_by(64) {
        // SAFETY: Reading from static array within bounds.
        unsafe {
            let ptr = FLUSH_AREA.as_ptr().add(i);
            sum = sum.wrapping_add(core::ptr::read_volatile(ptr) as u64);
        }
    }

    core::hint::black_box(sum);
}
