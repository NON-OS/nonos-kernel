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

use super::super::super::constants::*;
use super::super::super::error::NvmeError;
use super::super::super::types::ControllerCapabilities;
use crate::memory::mmio::{mmio_r32, mmio_w32};
use crate::memory::addr::VirtAddr;

pub fn disable_controller(mmio_base: usize) -> Result<(), NvmeError> {
    let cc = mmio_r32(VirtAddr::new((mmio_base + REG_CC) as u64));
    if (cc & CC_EN) != 0 {
        mmio_w32(VirtAddr::new((mmio_base + REG_CC) as u64), cc & !CC_EN);
        if !wait_csts(mmio_base, |csts| (csts & CSTS_RDY) == 0, DISABLE_TIMEOUT_SPINS) {
            return Err(NvmeError::ControllerDisableTimeout);
        }
    }
    Ok(())
}

pub fn enable_controller(mmio_base: usize, caps: &ControllerCapabilities) -> Result<(), NvmeError> {
    let csts = mmio_r32(VirtAddr::new((mmio_base + REG_CSTS) as u64));
    if (csts & CSTS_CFS) != 0 {
        return Err(NvmeError::ControllerFatalStatus);
    }
    let mps = (PAGE_SHIFT - 12) as u32;
    let mpsmin = caps.memory_page_size_min_shift.saturating_sub(12);
    let mps = if mps < mpsmin as u32 { mpsmin as u32 } else { mps };
    let mut cc: u32 = CC_EN | CC_CSS_NVM;
    cc |= (mps & 0xF) << CC_MPS_SHIFT;
    cc |= cc_sqes(6);
    cc |= cc_cqes(4);
    mmio_w32(VirtAddr::new((mmio_base + REG_CC) as u64), cc);
    if !wait_csts(mmio_base, |csts| (csts & CSTS_RDY) != 0, ENABLE_TIMEOUT_SPINS) {
        return Err(NvmeError::ControllerEnableTimeout);
    }
    let csts = mmio_r32(VirtAddr::new((mmio_base + REG_CSTS) as u64));
    if (csts & CSTS_CFS) != 0 {
        return Err(NvmeError::ControllerFatalStatus);
    }
    Ok(())
}

pub(super) fn wait_csts<F: Fn(u32) -> bool>(
    mmio_base: usize,
    predicate: F,
    mut spins: u32,
) -> bool {
    while spins > 0 {
        let csts = mmio_r32(VirtAddr::new((mmio_base + REG_CSTS) as u64));
        if predicate(csts) {
            return true;
        }
        spins -= 1;
        core::hint::spin_loop();
    }
    false
}
