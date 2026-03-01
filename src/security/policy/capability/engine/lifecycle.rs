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

use core::sync::atomic::Ordering;
use alloc::vec::Vec;

use crate::security::policy::capability::isolation::IsolationLevel;
use crate::security::policy::capability::violations::{SecurityViolation, ViolationSeverity};

use super::types::CapabilityEngine;

impl CapabilityEngine {
    pub(super) fn log_violation(&self, violation: SecurityViolation) {
        self.violation_log.write().push(violation.clone());

        if matches!(
            violation.severity,
            ViolationSeverity::Critical | ViolationSeverity::Emergency
        ) {
            self.emergency_lockdown.store(true, Ordering::Release);
        }
    }

    pub fn destroy_chamber(&self, chamber_id: u64) -> Result<(), &'static str> {
        let mut chambers = self.chambers.write();
        let chamber = chambers.remove(&chamber_id).ok_or("Chamber not found")?;

        let mut ephemeral_keys = chamber.ephemeral_keys.write();
        for (_, key) in ephemeral_keys.iter_mut() {
            crate::crypto::secure_zero(key);
        }
        ephemeral_keys.clear();

        let mut regions = chamber.sealed_memory_regions.write();
        for region in regions.iter_mut() {
            crate::crypto::secure_zero(&mut region.encryption_key);
            if region.ephemeral {
                crate::crypto::secure_erase_memory_region(
                    region.start_addr as usize,
                    region.size as usize,
                )?;
            }
        }
        regions.clear();

        let mut active_processes = self.active_processes.write();
        let process_id = chamber.execution_context.read().process_id;
        active_processes.remove(&process_id);

        Ok(())
    }

    pub fn emergency_lockdown(&self) {
        self.emergency_lockdown.store(true, Ordering::Release);

        let chamber_ids: Vec<u64> = self.chambers.read().keys().copied().collect();
        for chamber_id in chamber_ids {
            if let Some(chamber) = self.chambers.read().get(&chamber_id) {
                if matches!(
                    chamber.level,
                    IsolationLevel::Ephemeral | IsolationLevel::ZeroState
                ) {
                    let _ = self.destroy_chamber(chamber_id);
                }
            }
        }
    }
}
