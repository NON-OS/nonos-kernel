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
use alloc::{vec::Vec, boxed::Box, collections::BTreeMap};

use crate::security::policy::capability::isolation::IsolationChamber;
use crate::security::policy::capability::types::CapabilitySet;
use crate::security::policy::capability::violations::SecurityViolation;

pub struct CapabilityEngine {
    pub(super) chambers: RwLock<BTreeMap<u64, Box<IsolationChamber>>>,
    pub(super) capability_registry: RwLock<BTreeMap<u64, CapabilitySet>>,
    pub(super) signing_key: [u8; 32],
    pub(super) chamber_counter: AtomicU64,
    pub(super) active_processes: RwLock<BTreeMap<u64, u64>>,
    pub(super) violation_log: RwLock<Vec<SecurityViolation>>,
    pub(super) quantum_rng: Mutex<[u8; 32]>,
    pub(super) attestation_root: [u8; 32],
    pub(super) emergency_lockdown: AtomicBool,
}
