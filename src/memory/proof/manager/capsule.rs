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
use super::helpers::get_timestamp;
use super::state::ProofSystem;
use crate::memory::addr::PhysAddr;
use crate::memory::layout;
use core::sync::atomic::Ordering;

impl ProofSystem {
    pub(super) fn create_capsule(
        &self,
        start: PhysAddr,
        end: PhysAddr,
        tag: CapTag,
        permissions: CapsulePermissions,
    ) -> Result<u64, &'static str> {
        if start >= end {
            return Err("Invalid memory region");
        }
        if end.as_u64() - start.as_u64() < layout::PAGE_SIZE as u64 {
            return Err("Capsule too small");
        }

        let capsule_id = self.next_capsule_id.fetch_add(1, Ordering::Relaxed);
        let creation_time = get_timestamp();
        let memory_region = MemoryRegion { start, end, tag };
        let integrity_hash = self.compute_region_hash(&memory_region, creation_time);
        let access_key = self.derive_access_key(capsule_id, &integrity_hash);

        let capsule = CryptographicCapsule {
            capsule_id,
            memory_region,
            integrity_hash,
            access_key,
            permissions,
            creation_time,
        };
        self.capsules.write().insert(capsule_id, capsule);
        self.audit(AuditOperation::Create, capsule_id, AuditResult::Success);
        Ok(capsule_id)
    }

    pub(super) fn seal_capsule(&self, capsule_id: u64) -> Result<(), &'static str> {
        let mut capsules = self.capsules.write();
        match capsules.get_mut(&capsule_id) {
            Some(capsule) if !capsule.permissions.sealed => {
                capsule.permissions.sealed = true;
                capsule.integrity_hash =
                    self.compute_region_hash(&capsule.memory_region, get_timestamp());
                self.audit(AuditOperation::Seal, capsule_id, AuditResult::Success);
                Ok(())
            }
            Some(_) => {
                self.audit(AuditOperation::Seal, capsule_id, AuditResult::Failure);
                Err("Capsule already sealed")
            }
            None => {
                self.audit(AuditOperation::Seal, capsule_id, AuditResult::Failure);
                Err("Capsule not found")
            }
        }
    }
}
