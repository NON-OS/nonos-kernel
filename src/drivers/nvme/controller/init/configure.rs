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

use super::super::super::constants::{aqa, REG_ACQ, REG_AQA, REG_ASQ, REG_INTMC, REG_INTMS};
use super::super::super::error::NvmeError;
use super::super::super::queue::AdminQueue;
use crate::drivers::pci::PciDevice;
use crate::memory::mmio::mmio_w32;
use crate::memory::addr::VirtAddr;

pub fn configure_admin_queue(mmio_base: usize, admin_queue: &AdminQueue) -> Result<(), NvmeError> {
    let depth = admin_queue.depth();
    let aqa_val = aqa(depth, depth);
    mmio_w32(VirtAddr::new((mmio_base + REG_AQA) as u64), aqa_val);
    crate::memory::mmio::mmio_w64(
        VirtAddr::new((mmio_base + REG_ASQ) as u64),
        admin_queue.sq_phys(),
    );
    crate::memory::mmio::mmio_w64(
        VirtAddr::new((mmio_base + REG_ACQ) as u64),
        admin_queue.cq_phys(),
    );
    Ok(())
}

pub fn unmask_interrupts(mmio_base: usize) {
    mmio_w32(VirtAddr::new((mmio_base + REG_INTMS) as u64), 0);
    mmio_w32(VirtAddr::new((mmio_base + REG_INTMC) as u64), 0xFFFF_FFFF);
    mmio_w32(VirtAddr::new((mmio_base + REG_INTMC) as u64), 0);
}

pub fn configure_msix(pci: &mut PciDevice, vector: u8) -> Result<(), NvmeError> {
    pci.configure_msix(vector).map_err(|_| NvmeError::MsixConfigurationFailed)
}
