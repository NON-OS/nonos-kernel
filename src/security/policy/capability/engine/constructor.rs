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

use core::sync::atomic::{AtomicU64, AtomicBool};
use spin::{RwLock, Mutex};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::types::CapabilityEngine;

impl CapabilityEngine {
    pub fn new() -> Result<Self, &'static str> {
        let signing_key = crate::crypto::generate_secure_key();

        let mut quantum_rng = [0u8; 32];
        crate::crypto::fill_random(&mut quantum_rng);

        let mut attestation_root = [0u8; 32];
        crate::crypto::fill_random(&mut attestation_root);

        Ok(Self {
            chambers: RwLock::new(BTreeMap::new()),
            capability_registry: RwLock::new(BTreeMap::new()),
            signing_key,
            chamber_counter: AtomicU64::new(1),
            active_processes: RwLock::new(BTreeMap::new()),
            violation_log: RwLock::new(Vec::new()),
            quantum_rng: Mutex::new(quantum_rng),
            attestation_root,
            emergency_lockdown: AtomicBool::new(false),
        })
    }
}
