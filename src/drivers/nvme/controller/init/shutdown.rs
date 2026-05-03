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
use super::enable::wait_csts;
use crate::memory::addr::VirtAddr;
use crate::memory::mmio::{mmio_r32, mmio_w32};

pub fn shutdown_controller(mmio_base: usize) -> Result<(), NvmeError> {
    let cc = mmio_r32(VirtAddr::new((mmio_base + REG_CC) as u64));
    let cc_shutdown = (cc & !(0x3 << CC_SHN_SHIFT)) | CC_SHN_NORMAL;
    mmio_w32(VirtAddr::new((mmio_base + REG_CC) as u64), cc_shutdown);
    if !wait_csts(mmio_base, |csts| ((csts >> 2) & 0x3) == 2, ENABLE_TIMEOUT_SPINS) {
        return Err(NvmeError::ControllerDisableTimeout);
    }
    mmio_w32(VirtAddr::new((mmio_base + REG_CC) as u64), cc & !CC_EN);
    Ok(())
}

pub fn subsystem_reset(mmio_base: usize, caps: &ControllerCapabilities) -> Result<(), NvmeError> {
    if !caps.subsystem_reset_supported {
        return Err(NvmeError::ControllerFatalStatus);
    }
    mmio_w32(VirtAddr::new((mmio_base + REG_NSSR) as u64), 0x4E564D65);
    let mut spins = ENABLE_TIMEOUT_SPINS;
    while spins > 0 {
        let csts = mmio_r32(VirtAddr::new((mmio_base + REG_CSTS) as u64));
        if (csts & CSTS_NSSRO) != 0 {
            mmio_w32(VirtAddr::new((mmio_base + REG_CSTS) as u64), CSTS_NSSRO);
            return Ok(());
        }
        spins -= 1;
        core::hint::spin_loop();
    }
    Err(NvmeError::ControllerDisableTimeout)
}
