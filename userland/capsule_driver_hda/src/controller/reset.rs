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

use crate::constants::{GCTL, GCTL_CRST};
use crate::error::{HdaError, HdaResult};
use crate::regs::Regs;

const RESET_SPINS: u32 = 1_000_000;

pub fn leave_reset(regs: Regs) -> HdaResult<()> {
    let gctl = unsafe { regs.r32(GCTL) };
    if gctl & GCTL_CRST == 0 {
        unsafe { regs.w32(GCTL, gctl | GCTL_CRST) };
    }
    let mut spins = 0u32;
    while spins < RESET_SPINS {
        if unsafe { regs.r32(GCTL) } & GCTL_CRST != 0 {
            return Ok(());
        }
        spins = spins.wrapping_add(1);
    }
    Err(HdaError::ControllerResetTimeout)
}
