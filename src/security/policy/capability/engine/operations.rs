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
use alloc::format;

use crate::crypto::rng::random_u64;
use crate::security::policy::capability::types::Capability;
use crate::security::policy::capability::isolation::IsolationLevel;
use crate::security::policy::capability::quantum::QuantumState;
use crate::security::policy::capability::violations::{SecurityViolation, ViolationType, ViolationSeverity};

use super::types::CapabilityEngine;

impl CapabilityEngine {
    pub fn enter_chamber(&self, chamber_id: u64, process_id: u64) -> Result<(), &'static str> {
        if self.emergency_lockdown.load(Ordering::Acquire) {
            return Err("System in emergency lockdown");
        }

        let chambers = self.chambers.read();
        let chamber = chambers.get(&chamber_id).ok_or("Chamber not found")?;

        chamber
            .last_access_timestamp
            .store(crate::time::get_kernel_time_ns(), Ordering::Release);
        chamber.access_count.fetch_add(1, Ordering::Release);

        {
            let mut execution_context = chamber.execution_context.write();
            execution_context.process_id = process_id;
        }

        self.active_processes
            .write()
            .insert(process_id, chamber_id);

        if matches!(chamber.level, IsolationLevel::QuantumSecure) {
            if let Some(ref quantum_state) = chamber.quantum_entanglement {
                self.perform_quantum_measurement(quantum_state)?;
            }
        }

        Ok(())
    }

    pub(super) fn perform_quantum_measurement(&self, quantum_state: &QuantumState) -> Result<(), &'static str> {
        let current_time = crate::time::get_kernel_time_ns();

        for particle in &quantum_state.entangled_particles {
            if current_time - particle.last_measurement > 1_000_000_000 {
                let _measurement_result = (random_u64() as f64) / (u64::MAX as f64);
            }
        }

        Ok(())
    }

    pub fn check_capability(
        &self,
        process_id: u64,
        capability: Capability,
    ) -> Result<bool, &'static str> {
        if self.emergency_lockdown.load(Ordering::Acquire) {
            return Err("System in emergency lockdown");
        }

        let active_processes = self.active_processes.read();
        let chamber_id = active_processes
            .get(&process_id)
            .ok_or("Process not in any chamber")?;

        let chambers = self.chambers.read();
        let chamber = chambers.get(chamber_id).ok_or("Chamber not found")?;

        if !chamber.capability_whitelist.has_capability(capability) {
            self.log_violation(SecurityViolation {
                timestamp: crate::time::get_kernel_time_ns(),
                process_id,
                chamber_id: Some(*chamber_id),
                violation_type: ViolationType::UnauthorizedCapabilityUse,
                attempted_capability: Some(capability),
                severity: ViolationSeverity::Medium,
                context: format!(
                    "Process {} attempted to use capability {:?}",
                    process_id, capability
                ),
            });

            chamber.violation_count.fetch_add(1, Ordering::Release);
            return Ok(false);
        }

        if !chamber.capability_whitelist.use_capability() {
            self.log_violation(SecurityViolation {
                timestamp: crate::time::get_kernel_time_ns(),
                process_id,
                chamber_id: Some(*chamber_id),
                violation_type: ViolationType::CapabilityExpired,
                attempted_capability: Some(capability),
                severity: ViolationSeverity::High,
                context: format!(
                    "Process {} used expired capability {:?}",
                    process_id, capability
                ),
            });

            return Ok(false);
        }

        Ok(true)
    }
}
