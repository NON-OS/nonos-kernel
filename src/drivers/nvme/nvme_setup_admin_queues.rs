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

use crate::arch::x86_64::pci::mmio::{write_u32, write_u64};
use crate::mem::allocator::allocate_pages;
use super::types::NvmeController;

pub fn nvme_setup_admin_queues(controller: &mut NvmeController) -> Result<(), &'static str> {
    let asq_pages = allocate_pages(1)?;
    let acq_pages = allocate_pages(1)?;

    controller.admin_queue.submission_queue.base_addr = asq_pages;
    controller.admin_queue.completion_queue.base_addr = acq_pages;
    controller.admin_queue.submission_queue.size = 64;
    controller.admin_queue.completion_queue.size = 64;

    write_u64(controller.bar0_base + 0x28, asq_pages);
    write_u64(controller.bar0_base + 0x30, acq_pages);

    let aqa = ((63 << 16) | 63) as u32;
    write_u32(controller.bar0_base + 0x24, aqa);

    Ok(())
}