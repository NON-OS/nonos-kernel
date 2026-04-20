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

use crate::arch::x86_64::pci::mmio::write_u32;
use super::types::NvmeController;

pub fn nvme_wait_for_completion(controller: &mut NvmeController) -> Result<(), &'static str> {
    let cq_base = controller.admin_queue.completion_queue.base_addr;
    let mut timeout = 10000;

    loop {
        let entry_addr = cq_base + (controller.admin_queue.cq_head as u64) * 16;
        let status = unsafe { core::ptr::read_volatile((entry_addr + 14) as *const u16) };

        if status & 1 != controller.admin_queue.cq_head & 1 {
            controller.admin_queue.cq_head = (controller.admin_queue.cq_head + 1) % 64;
            write_u32(controller.bar0_base + 0x1004, controller.admin_queue.cq_head as u32);
            break;
        }

        if timeout == 0 {
            return Err("NVMe command timeout");
        }
        timeout -= 1;
        crate::arch::x86_64::asm::pause();
    }
    Ok(())
}