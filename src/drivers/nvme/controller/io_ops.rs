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

use super::super::error::NvmeError;
use super::io;
use super::structure::NvmeController;
use x86_64::PhysAddr;

impl NvmeController {
    pub fn read(&self, lba: u64, count: u16, buffer_phys: PhysAddr) -> Result<(), NvmeError> {
        if !self.initialized {
            return Err(NvmeError::ControllerNotInitialized);
        }
        self.security.check_rate_limit()?;
        let ns = {
            let ns_mgr = self.namespaces.lock();
            ns_mgr.first().cloned().ok_or(NvmeError::NamespaceNotReady)?
        };
        let queue_idx = self.current_cpu_queue_index();
        let io_queues = self.io_queues.lock();
        let io_queue = io_queues
            .get(queue_idx)
            .or_else(|| io_queues.first())
            .ok_or(NvmeError::IoQueueNotReady)?;
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
        let queue_idx = self.current_cpu_queue_index();
        let io_queues = self.io_queues.lock();
        let io_queue = io_queues
            .get(queue_idx)
            .or_else(|| io_queues.first())
            .ok_or(NvmeError::IoQueueNotReady)?;
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
}
