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

use alloc::vec::Vec;
use spin::Mutex;
use x86_64::PhysAddr;

use crate::drivers::pci::{PciBar, PciDevice};

use super::super::constants::*;
use super::super::error::NvmeError;
use super::super::namespace::{Namespace, NamespaceManager};
use super::super::queue::{AdminQueue, IoQueue};
use super::super::security::SecurityContext;
use super::super::stats::{NvmeStats, NvmeStatsSnapshot};
use super::super::types::{ControllerCapabilities, ControllerIdentity, ControllerVersion};
use super::{admin, init, io};

pub struct NvmeController {
    pci: PciDevice,
    mmio_base: usize,
    doorbell_stride: u32,
    capabilities: ControllerCapabilities,
    version: ControllerVersion,
    identity: Option<ControllerIdentity>,
    admin_queue: Mutex<AdminQueue>,
    io_queues: Mutex<Vec<IoQueue>>,
    namespaces: Mutex<NamespaceManager>,
    stats: NvmeStats,
    security: SecurityContext,
    initialized: bool,
}

impl NvmeController {
    pub fn new(pci: PciDevice) -> Result<Self, NvmeError> {
        let bar = pci
            .get_bar(NVME_BAR_INDEX as usize)
            .ok_or(NvmeError::Bar0NotMmio)?;

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
        })
    }

    pub fn init(&mut self) -> Result<(), NvmeError> {
        init::disable_controller(self.mmio_base)?;

        {
            let admin = self.admin_queue.lock();
            init::configure_admin_queue(self.mmio_base, &admin)?;
        }

        init::unmask_interrupts(self.mmio_base);

        if let Some(vector) = crate::interrupts::allocate_vector() {
            let _ = init::configure_msix(&mut self.pci, vector);
        }

        init::enable_controller(self.mmio_base, &self.capabilities)?;

        {
            let admin = self.admin_queue.lock();
            let identity = admin::identify_controller(&admin)?;
            self.identity = Some(identity);
        }

        self.discover_namespaces()?;
        self.create_default_io_queue()?;
        self.initialized = true;
        Ok(())
    }

    fn discover_namespaces(&self) -> Result<(), NvmeError> {
        let admin = self.admin_queue.lock();
        let nsids = admin::get_active_namespace_list(&admin, 0)?;
        if nsids.is_empty() {
            return Err(NvmeError::NoActiveNamespaces);
        }

        let mut ns_manager = self.namespaces.lock();
        for nsid in nsids {
            if let Ok(ns) = admin::identify_namespace(&admin, nsid) {
                ns_manager.add(ns);
            }
        }

        self.stats.set_namespace_count(ns_manager.count() as u32);
        Ok(())
    }

    fn create_default_io_queue(&self) -> Result<(), NvmeError> {
        let qid: u16 = 1;
        let depth = IO_QUEUE_DEPTH;
        let sq_doorbell =
            init::calculate_sq_doorbell(self.mmio_base, self.doorbell_stride, qid);
        let cq_doorbell =
            init::calculate_cq_doorbell(self.mmio_base, self.doorbell_stride, qid);

        let io_queue = IoQueue::new(qid, depth, depth, sq_doorbell, cq_doorbell)?;

        {
            let admin = self.admin_queue.lock();

            admin::create_io_completion_queue(
                &admin,
                qid,
                depth,
                io_queue.cq_phys(),
                0,
                false,
            )?;

            admin::create_io_submission_queue(&admin, qid, depth, io_queue.sq_phys(), qid, 0)?;
        }

        self.io_queues.lock().push(io_queue);
        Ok(())
    }

    pub fn read(&self, lba: u64, count: u16, buffer_phys: PhysAddr) -> Result<(), NvmeError> {
        if !self.initialized {
            return Err(NvmeError::ControllerNotInitialized);
        }

        self.security.check_rate_limit()?;
        let ns = {
            let ns_mgr = self.namespaces.lock();
            ns_mgr.first().cloned().ok_or(NvmeError::NamespaceNotReady)?
        };

        let io_queues = self.io_queues.lock();
        let io_queue = io_queues.first().ok_or(NvmeError::IoQueueNotReady)?;
        io::read_blocks(io_queue, &ns, lba, count, buffer_phys, &self.stats)
    }

    pub fn write(&self, lba: u64, count: u16, buffer_phys: PhysAddr) -> Result<(), NvmeError> {
        if !self.initialized {
            return Err(NvmeError::ControllerNotInitialized);
        }

        self.security.check_rate_limit()?;

        let ns = {
            let ns_mgr = self.namespaces.lock();
            ns_mgr.first().cloned().ok_or(NvmeError::NamespaceNotReady)?
        };

        let io_queues = self.io_queues.lock();
        let io_queue = io_queues.first().ok_or(NvmeError::IoQueueNotReady)?;
        io::write_blocks(io_queue, &ns, lba, count, buffer_phys, &self.stats)
    }

    pub fn flush(&self) -> Result<(), NvmeError> {
        if !self.initialized {
            return Err(NvmeError::ControllerNotInitialized);
        }

        let ns = {
            let ns_mgr = self.namespaces.lock();
            ns_mgr.first().cloned().ok_or(NvmeError::NamespaceNotReady)?
        };

        let io_queues = self.io_queues.lock();
        let io_queue = io_queues.first().ok_or(NvmeError::IoQueueNotReady)?;
        io::flush(io_queue, &ns, &self.stats)
    }

    pub fn trim(&self, ranges: &[(u64, u32)]) -> Result<(), NvmeError> {
        if !self.initialized {
            return Err(NvmeError::ControllerNotInitialized);
        }

        let ns = {
            let ns_mgr = self.namespaces.lock();
            ns_mgr.first().cloned().ok_or(NvmeError::NamespaceNotReady)?
        };

        let io_queues = self.io_queues.lock();
        let io_queue = io_queues.first().ok_or(NvmeError::IoQueueNotReady)?;
        io::trim(io_queue, &ns, ranges, &self.stats)
    }

    pub fn get_stats(&self) -> NvmeStatsSnapshot {
        self.stats.snapshot()
    }

    pub fn reset_stats(&self) {
        self.stats.reset();
    }

    pub fn get_namespace(&self, nsid: u32) -> Option<Namespace> {
        self.namespaces.lock().get(nsid).cloned()
    }

    pub fn get_first_namespace(&self) -> Option<Namespace> {
        self.namespaces.lock().first().cloned()
    }

    pub fn namespace_count(&self) -> usize {
        self.namespaces.lock().count()
    }

    pub fn capabilities(&self) -> &ControllerCapabilities {
        &self.capabilities
    }

    pub fn version(&self) -> &ControllerVersion {
        &self.version
    }

    pub fn identity(&self) -> Option<&ControllerIdentity> {
        self.identity.as_ref()
    }

    pub fn set_rate_limit(&self, limit: u32) {
        self.security.set_rate_limit(limit);
    }

    pub fn set_timeout(&self, spins: u32) {
        self.admin_queue.lock().set_timeout(spins);
        for queue in self.io_queues.lock().iter() {
            queue.set_timeout(spins);
        }
    }

    pub fn get_smart_log(&self, nsid: u32) -> Result<admin::SmartLog, NvmeError> {
        if !self.initialized {
            return Err(NvmeError::ControllerNotInitialized);
        }

        let admin = self.admin_queue.lock();
        admin::get_smart_log(&admin, nsid)
    }

    pub fn shutdown(&self) -> Result<(), NvmeError> {
        if !self.initialized {
            return Ok(());
        }

        init::shutdown_controller(self.mmio_base)
    }
}

// SAFETY: NvmeController uses internal locking for thread safety
unsafe impl Send for NvmeController {}
unsafe impl Sync for NvmeController {}
