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
use super::types::{NvmeController, NvmeCommand};

pub fn nvme_submit_admin_command(controller: &mut NvmeController, command: NvmeCommand) -> Result<(), &'static str> {
    let sq_base = controller.admin_queue.submission_queue.base_addr;
    let slot = controller.admin_queue.sq_tail as u64;
    let cmd_addr = sq_base + slot * 64;

    unsafe {
        core::ptr::write_volatile(cmd_addr as *mut NvmeCommand, command);
    }

    controller.admin_queue.sq_tail = (controller.admin_queue.sq_tail + 1) % 64;
    write_u32(controller.bar0_base + 0x1000, controller.admin_queue.sq_tail as u32);

    Ok(())
}