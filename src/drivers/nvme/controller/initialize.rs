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
use super::structure::NvmeController;
use super::{admin, init};

impl NvmeController {
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
        self.create_multiqueue_io_queues()?;
        self.initialized = true;
        Ok(())
    }

    pub(super) fn discover_namespaces(&self) -> Result<(), NvmeError> {
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

    pub fn shutdown(&self) -> Result<(), NvmeError> {
        if !self.initialized {
            return Ok(());
        }
        init::shutdown_controller(self.mmio_base)
    }
}
