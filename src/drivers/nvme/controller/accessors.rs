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

use super::super::error::NvmeError;
use super::super::namespace::Namespace;
use super::super::stats::NvmeStatsSnapshot;
use super::super::types::{ControllerCapabilities, ControllerIdentity, ControllerVersion};
use super::admin;
use super::structure::NvmeController;

impl NvmeController {
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

    pub fn io_queues_ref(
        &self,
    ) -> spin::MutexGuard<'_, alloc::vec::Vec<super::super::queue::IoQueue>> {
        self.io_queues.lock()
    }
}
