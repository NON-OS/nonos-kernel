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

use crate::constants::{CC_EN, CC_IOCQES_16, CC_IOSQES_64, CSTS_CFS, CSTS_RDY, REG_CC, REG_CSTS};
use crate::controller::ControllerInfo;
use crate::error::{NvmeError, NvmeResult};
use crate::regs::Regs;

const READY_POLL_LIMIT: u32 = 5_000_000;

pub fn reset_to_disabled(regs: Regs) -> NvmeResult<()> {
    unsafe { regs.w32(REG_CC, 0) };
    wait_ready(regs, false)
}

pub fn enable(regs: Regs, info: ControllerInfo) -> NvmeResult<()> {
    if info.min_page_shift() != 12 {
        return Err(NvmeError::UnsupportedPageSize);
    }
    let cc = CC_EN | CC_IOSQES_64 | CC_IOCQES_16;
    unsafe { regs.w32(REG_CC, cc) };
    wait_ready(regs, true)
}

fn wait_ready(regs: Regs, want_ready: bool) -> NvmeResult<()> {
    for _ in 0..READY_POLL_LIMIT {
        let csts = unsafe { regs.r32(REG_CSTS) };
        if (csts & CSTS_CFS) != 0 {
            return Err(NvmeError::UnsupportedController);
        }
        if ((csts & CSTS_RDY) != 0) == want_ready {
            return Ok(());
        }
        core::hint::spin_loop();
    }
    Err(NvmeError::ControllerTimeout)
}
