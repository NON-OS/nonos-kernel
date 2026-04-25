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
use super::state::ProofSystem;

impl ProofSystem {
    pub(super) fn verify_capsule_integrity(&self, capsule_id: u64) -> Result<bool, &'static str> {
        let capsules = self.capsules.read();
        match capsules.get(&capsule_id) {
            Some(capsule) => {
                let current_hash =
                    self.compute_region_hash(&capsule.memory_region, capsule.creation_time);
                let integrity_valid = current_hash == capsule.integrity_hash;
                self.audit(
                    AuditOperation::Verify,
                    capsule_id,
                    if integrity_valid { AuditResult::Success } else { AuditResult::Violation },
                );
                Ok(integrity_valid)
            }
            None => {
                self.audit(AuditOperation::Verify, capsule_id, AuditResult::Failure);
                Err("Capsule not found")
            }
        }
    }
}
