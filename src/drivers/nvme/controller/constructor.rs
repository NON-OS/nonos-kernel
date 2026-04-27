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

use super::super::constants::ADMIN_QUEUE_DEPTH;
use super::super::error::NvmeError;
use super::super::namespace::NamespaceManager;
use super::super::queue::AdminQueue;
use super::super::security::SecurityContext;
use super::super::stats::NvmeStats;
use super::super::types::ControllerVersion;
use super::init;
use super::structure::NvmeController;
use crate::drivers::pci::{PciBar, PciDevice};
use alloc::vec::Vec;
use spin::Mutex;

impl NvmeController {
    pub fn new(pci: PciDevice) -> Result<Self, NvmeError> {
        let bar = pci.get_bar(0).ok_or(NvmeError::Bar0NotMmio)?;
        let mmio_base = match bar {
            PciBar::Memory { address, .. } => address.as_u64() as usize,
            _ => return Err(NvmeError::Bar0NotMmio),
        };
        let caps = init::read_capabilities(mmio_base)?;
        let version_raw = init::read_version(mmio_base);
        let version = ControllerVersion::from_register(version_raw);
        let dstrd = init::get_doorbell_stride(mmio_base);
        let sq_doorbell = init::calculate_sq_doorbell(mmio_base, dstrd, 0);
        let cq_doorbell = init::calculate_cq_doorbell(mmio_base, dstrd, 0);
        let admin_queue = AdminQueue::new(ADMIN_QUEUE_DEPTH, sq_doorbell, cq_doorbell)?;
        Ok(Self {
            pci,
            mmio_base,
            doorbell_stride: dstrd,
            capabilities: caps,
            version,
            identity: None,
            admin_queue: Mutex::new(admin_queue),
            io_queues: Mutex::new(Vec::new()),
            namespaces: Mutex::new(NamespaceManager::new()),
            stats: NvmeStats::new(),
            security: SecurityContext::new(),
            initialized: false,
            cpu_queue_map: Mutex::new(Vec::new()),
        })
    }
}
