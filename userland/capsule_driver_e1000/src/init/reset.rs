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

//! Hardware reset + IRQ quiesce + link bring-up. CTRL.RST is
//! self-clearing; the loop bound is generous because the device
//! takes a few microseconds to settle. After reset the firmware
//! restores most defaults but leaves all IMS bits set, so the
//! capsule masks every cause through IMC and reads ICR to clear
//! any latched bits before enabling the link.

use crate::constants::regs::{REG_CTRL, REG_ICR, REG_IMC};
use crate::constants::status::{CTRL_ASDE, CTRL_LRST, CTRL_RST, CTRL_SLU};
use crate::regs::Regs;

const RESET_POLL_BUDGET: u32 = 100_000;

pub fn run(regs: &Regs) -> Result<(), &'static str> {
    // SAFETY: eK@nonos.systems — `regs` carries a base from a
    // valid broker MmioMap grant; offsets are 32-bit aligned per
    // the 8254x manual.
    unsafe {
        let ctrl = regs.r32(REG_CTRL);
        regs.w32(REG_CTRL, ctrl | CTRL_RST);
        let mut spins = 0u32;
        while regs.r32(REG_CTRL) & CTRL_RST != 0 {
            spins += 1;
            if spins > RESET_POLL_BUDGET {
                return Err("CTRL.RST did not self-clear");
            }
            core::hint::spin_loop();
        }
        regs.w32(REG_IMC, 0xFFFF_FFFF);
        let _ = regs.r32(REG_ICR);
        let mut ctrl = regs.r32(REG_CTRL);
        ctrl &= !CTRL_LRST;
        ctrl |= CTRL_SLU | CTRL_ASDE;
        regs.w32(REG_CTRL, ctrl);
    }
    Ok(())
}
