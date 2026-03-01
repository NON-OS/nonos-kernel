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

use core::sync::atomic::{AtomicU64, Ordering};
use spin::{RwLock, Mutex};
use alloc::{boxed::Box, collections::BTreeMap, vec::Vec, format};

use crate::crypto::rng::random_u64;
use crate::security::policy::capability::types::CapabilitySet;
use crate::security::policy::capability::isolation::{IsolationLevel, IsolationChamber, ExecutionContext};
use crate::security::policy::capability::quantum::{QuantumState, QuantumParticle};
use crate::security::policy::capability::types::Capability;
use crate::security::policy::capability::stats::ChamberStats;

use super::types::CapabilityEngine;

impl CapabilityEngine {
    pub fn create_isolation_chamber(
        &self,
        level: IsolationLevel,
        initial_caps: &[Capability],
    ) -> Result<u64, &'static str> {
        if self.emergency_lockdown.load(Ordering::Acquire) {
            return Err("System in emergency lockdown");
        }

        let chamber_id = self.chamber_counter.fetch_add(1, Ordering::Release);
        let mut encryption_key = [0u8; 32];
        crate::crypto::fill_random(&mut encryption_key);

        let capability_set = CapabilitySet::new();
        for &cap in initial_caps {
            capability_set.grant_capability(cap);
        }

        let execution_context = ExecutionContext {
            process_id: 0,
            thread_count: 0,
            cpu_quota: match level {
                IsolationLevel::None | IsolationLevel::Basic => 1000,
                IsolationLevel::Cryptographic => 500,
                IsolationLevel::Ephemeral => 250,
                IsolationLevel::ZeroState => 100,
                IsolationLevel::QuantumSecure => 50,
            },
            memory_limit: match level {
                IsolationLevel::None | IsolationLevel::Basic => 1024 * 1024 * 100,
                IsolationLevel::Cryptographic => 1024 * 1024 * 50,
                IsolationLevel::Ephemeral => 1024 * 1024 * 25,
                IsolationLevel::ZeroState => 1024 * 1024 * 10,
                IsolationLevel::QuantumSecure => 1024 * 1024 * 5,
            },
            io_bandwidth_limit: 1024 * 1024,
            syscall_budget: 1000,
            crypto_operations_budget: 100,
            network_connections_limit: 10,
            file_handles_limit: 50,
            execution_time_limit: 60_000_000_000,
            quantum_operations_budget: match level {
                IsolationLevel::QuantumSecure => 10,
                _ => 0,
            },
        };

        let quantum_state = if matches!(level, IsolationLevel::QuantumSecure) {
            Some(self.create_quantum_state()?)
        } else {
            None
        };

        let current_time = crate::time::get_kernel_time_ns();
        let _chamber_data = format!(
            "chamber_id:{},level:{:?},timestamp:{}",
            chamber_id, level, current_time
        );

        let mut chamber_signature = [0u8; 64];
        crate::crypto::fill_random(&mut chamber_signature[..32]);
        chamber_signature[32..].copy_from_slice(&self.signing_key);

        let chamber = Box::new(IsolationChamber {
            id: chamber_id,
            level,
            memory_encryption_key: encryption_key,
            sealed_memory_regions: RwLock::new(Vec::new()),
            capability_whitelist: capability_set,
            execution_context: RwLock::new(execution_context),
            attestation_chain: RwLock::new(Vec::new()),
            quantum_entanglement: quantum_state,
            ephemeral_keys: RwLock::new(BTreeMap::new()),
            secure_rng_state: Mutex::new({
                let mut state = [0u8; 32];
                crate::crypto::fill_random(&mut state);
                state
            }),
            chamber_signature,
            creation_timestamp: current_time,
            last_access_timestamp: AtomicU64::new(current_time),
            access_count: AtomicU64::new(0),
            violation_count: core::sync::atomic::AtomicU32::new(0),
            auto_destruct_timer: AtomicU64::new(0),
        });

        self.chambers.write().insert(chamber_id, chamber);
        Ok(chamber_id)
    }

    pub(super) fn create_quantum_state(&self) -> Result<QuantumState, &'static str> {
        let mut quantum_key = [0u8; 64];
        crate::crypto::fill_random(&mut quantum_key);

        let particles = (0..4)
            .map(|_| {
                let mut state_vector = [0f64; 4];
                for i in 0..4 {
                    state_vector[i] = (random_u64() as f64) / (u64::MAX as f64);
                }

                QuantumParticle {
                    state_vector,
                    spin: (random_u64() as f64) / (u64::MAX as f64) * 2.0 - 1.0,
                    position_uncertainty: 0.1,
                    momentum_uncertainty: 0.1,
                    last_measurement: crate::time::get_kernel_time_ns(),
                }
            })
            .collect();

        Ok(QuantumState {
            entangled_particles: particles,
            decoherence_timer: AtomicU64::new(0),
            quantum_key,
        })
    }

    pub fn get_chamber_stats(&self, chamber_id: u64) -> Result<ChamberStats, &'static str> {
        let chambers = self.chambers.read();
        let chamber = chambers.get(&chamber_id).ok_or("Chamber not found")?;

        let stats = ChamberStats {
            id: chamber.id,
            level: chamber.level,
            access_count: chamber.access_count.load(Ordering::Acquire),
            violation_count: chamber.violation_count.load(Ordering::Acquire),
            sealed_regions_count: chamber.sealed_memory_regions.read().len(),
            attestation_chain_length: chamber.attestation_chain.read().len(),
            ephemeral_keys_count: chamber.ephemeral_keys.read().len(),
            creation_timestamp: chamber.creation_timestamp,
            last_access: chamber.last_access_timestamp.load(Ordering::Acquire),
        };
        Ok(stats)
    }
}
