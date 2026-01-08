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

use x86_64::VirtAddr;
use crate::memory::mmio::{mmio_r32, mmio_r64, mmio_w32, mmio_w64};
use crate::drivers::pci::PciDevice;
use super::super::constants::*;
use super::super::error::NvmeError;
use super::super::types::ControllerCapabilities;
use super::super::queue::AdminQueue;

pub fn read_capabilities(mmio_base: usize) -> Result<ControllerCapabilities, NvmeError> {
    // SAFETY: mmio_base is validated MMIO address from PCI BAR
    let cap = unsafe { mmio_r64(VirtAddr::new((mmio_base + REG_CAP) as u64)) };
    Ok(ControllerCapabilities::from_register(cap))
}

pub fn read_version(mmio_base: usize) -> u32 {
    // SAFETY: mmio_base is validated MMIO address from PCI BAR
    unsafe { mmio_r32(VirtAddr::new((mmio_base + REG_VS) as u64)) }
}

pub fn disable_controller(mmio_base: usize) -> Result<(), NvmeError> {
    // SAFETY: mmio_base is validated MMIO address from PCI BAR
    let cc = unsafe { mmio_r32(VirtAddr::new((mmio_base + REG_CC) as u64)) };

    if (cc & CC_EN) != 0 {
        // SAFETY: mmio_base is validated MMIO address from PCI BAR
        unsafe {
            mmio_w32(VirtAddr::new((mmio_base + REG_CC) as u64), cc & !CC_EN);
        }

        if !wait_for_csts(mmio_base, |csts| (csts & CSTS_RDY) == 0, DISABLE_TIMEOUT_SPINS) {
            return Err(NvmeError::ControllerDisableTimeout);
        }
    }

    Ok(())
}

pub fn enable_controller(
    mmio_base: usize,
    caps: &ControllerCapabilities,
) -> Result<(), NvmeError> {
    // SAFETY: mmio_base is validated MMIO address from PCI BAR
    let csts = unsafe { mmio_r32(VirtAddr::new((mmio_base + REG_CSTS) as u64)) };
    if (csts & CSTS_CFS) != 0 {
        return Err(NvmeError::ControllerFatalStatus);
    }

    let mps = (PAGE_SHIFT - 12) as u32;
    let mpsmin = caps.memory_page_size_min_shift.saturating_sub(12);
    let mps = if mps < mpsmin as u32 { mpsmin as u32 } else { mps };

    let mut cc: u32 = 0;
    cc |= CC_EN;
    cc |= CC_CSS_NVM;
    cc |= (mps & 0xF) << CC_MPS_SHIFT;
    cc |= cc_sqes(6);
    cc |= cc_cqes(4);

    // SAFETY: mmio_base is validated MMIO address from PCI BAR
    unsafe {
        mmio_w32(VirtAddr::new((mmio_base + REG_CC) as u64), cc);
    }

    if !wait_for_csts(mmio_base, |csts| (csts & CSTS_RDY) != 0, ENABLE_TIMEOUT_SPINS) {
        return Err(NvmeError::ControllerEnableTimeout);
    }

    // SAFETY: mmio_base is validated MMIO address from PCI BAR
    let csts = unsafe { mmio_r32(VirtAddr::new((mmio_base + REG_CSTS) as u64)) };
    if (csts & CSTS_CFS) != 0 {
        return Err(NvmeError::ControllerFatalStatus);
    }

    Ok(())
}

pub fn configure_admin_queue(
    mmio_base: usize,
    admin_queue: &AdminQueue,
) -> Result<(), NvmeError> {
    let depth = admin_queue.depth();
    let aqa = aqa(depth, depth);

    // SAFETY: mmio_base is validated MMIO address from PCI BAR
    unsafe {
        mmio_w32(VirtAddr::new((mmio_base + REG_AQA) as u64), aqa);
        mmio_w64(VirtAddr::new((mmio_base + REG_ASQ) as u64), admin_queue.sq_phys());
        mmio_w64(VirtAddr::new((mmio_base + REG_ACQ) as u64), admin_queue.cq_phys());
    }

    Ok(())
}

pub fn unmask_interrupts(mmio_base: usize) {
    // SAFETY: mmio_base is validated MMIO address from PCI BAR
    unsafe {
        mmio_w32(VirtAddr::new((mmio_base + REG_INTMS) as u64), 0);
        mmio_w32(VirtAddr::new((mmio_base + REG_INTMC) as u64), 0xFFFF_FFFF);
        mmio_w32(VirtAddr::new((mmio_base + REG_INTMC) as u64), 0);
    }
}

pub fn configure_msix(pci: &mut PciDevice, vector: u8) -> Result<(), NvmeError> {
    pci.configure_msix(vector)
        .map_err(|_| NvmeError::MsixConfigurationFailed)
}

pub fn get_doorbell_stride(mmio_base: usize) -> u32 {
    // SAFETY: mmio_base is validated MMIO address from PCI BAR
    let cap = unsafe { mmio_r64(VirtAddr::new((mmio_base + REG_CAP) as u64)) };
    cap_dstrd(cap)
}

pub fn calculate_sq_doorbell(mmio_base: usize, dstrd: u32, qid: u16) -> usize {
    mmio_base + doorbell_sq_offset(dstrd, qid)
}

pub fn calculate_cq_doorbell(mmio_base: usize, dstrd: u32, qid: u16) -> usize {
    mmio_base + doorbell_cq_offset(dstrd, qid)
}

fn wait_for_csts<F: Fn(u32) -> bool>(mmio_base: usize, predicate: F, mut spins: u32) -> bool {
    while spins > 0 {
        // SAFETY: mmio_base is validated MMIO address from PCI BAR
        let csts = unsafe { mmio_r32(VirtAddr::new((mmio_base + REG_CSTS) as u64)) };
        if predicate(csts) {
            return true;
        }
        spins -= 1;
        core::hint::spin_loop();
    }
    false
}

pub fn shutdown_controller(mmio_base: usize) -> Result<(), NvmeError> {
    // SAFETY: mmio_base is validated MMIO address from PCI BAR
    let cc = unsafe { mmio_r32(VirtAddr::new((mmio_base + REG_CC) as u64)) };

    let cc_shutdown = (cc & !(0x3 << CC_SHN_SHIFT)) | CC_SHN_NORMAL;
    // SAFETY: mmio_base is validated MMIO address from PCI BAR
    unsafe {
        mmio_w32(VirtAddr::new((mmio_base + REG_CC) as u64), cc_shutdown);
    }

    let shutdown_timeout = ENABLE_TIMEOUT_SPINS;
    if !wait_for_csts(
        mmio_base,
        |csts| ((csts >> 2) & 0x3) == 2,
        shutdown_timeout,
    ) {
        return Err(NvmeError::ControllerDisableTimeout);
    }

    // SAFETY: mmio_base is validated MMIO address from PCI BAR
    unsafe {
        mmio_w32(VirtAddr::new((mmio_base + REG_CC) as u64), cc & !CC_EN);
    }

    Ok(())
}

pub fn subsystem_reset(mmio_base: usize, caps: &ControllerCapabilities) -> Result<(), NvmeError> {
    if !caps.subsystem_reset_supported {
        return Err(NvmeError::ControllerFatalStatus);
    }

    // SAFETY: mmio_base is validated MMIO address from PCI BAR
    unsafe {
        mmio_w32(VirtAddr::new((mmio_base + REG_NSSR) as u64), 0x4E564D65);
    }

    let mut spins = ENABLE_TIMEOUT_SPINS;
    while spins > 0 {
        // SAFETY: mmio_base is validated MMIO address from PCI BAR
        let csts = unsafe { mmio_r32(VirtAddr::new((mmio_base + REG_CSTS) as u64)) };
        if (csts & CSTS_NSSRO) != 0 {
            // SAFETY: mmio_base is validated MMIO address from PCI BAR
            unsafe {
                mmio_w32(VirtAddr::new((mmio_base + REG_CSTS) as u64), CSTS_NSSRO);
            }
            return Ok(());
        }
        spins -= 1;
        core::hint::spin_loop();
    }

    Err(NvmeError::ControllerDisableTimeout)
}
