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

use super::super::types::*;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::AtomicU64;
use spin::{Mutex, RwLock};

pub(super) struct ProofSystem {
    pub capsules: RwLock<BTreeMap<u64, CryptographicCapsule>>,
    pub proofs: RwLock<BTreeMap<u64, MemoryProof>>,
    pub audit_log: Mutex<Vec<AuditEntry>>,
    pub next_capsule_id: AtomicU64,
    pub next_proof_id: AtomicU64,
}

impl ProofSystem {
    pub(super) const fn new() -> Self {
        Self {
            capsules: RwLock::new(BTreeMap::new()),
            proofs: RwLock::new(BTreeMap::new()),
            audit_log: Mutex::new(Vec::new()),
            next_capsule_id: AtomicU64::new(1),
            next_proof_id: AtomicU64::new(1),
        }
    }
}

pub(super) static PROOF_SYSTEM: ProofSystem = ProofSystem::new();
