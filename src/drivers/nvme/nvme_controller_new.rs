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

extern crate alloc;
use super::types::{AdminQueue, NvmeController};
use crate::drivers::pci::PciDevice;
use alloc::vec::Vec;

pub fn nvme_controller_new(pci_device: PciDevice) -> Result<NvmeController, &'static str> {
    let bar0 = pci_device.get_bar(0)?;
    let bar0_base = bar0 & !0xF;

    let mut controller = NvmeController {
        pci_device,
        bar0_base,
        admin_queue: super::nvme_admin_queue_new::nvme_admin_queue_new()?,
        io_queues: Vec::new(),
        namespace_count: 0,
    };

    super::nvme_controller_initialize::nvme_controller_initialize(&mut controller)?;
    Ok(controller)
}
