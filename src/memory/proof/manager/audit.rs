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

impl ProofSystem {
    pub(super) fn audit(&self, operation: AuditOperation, capsule_id: u64, result: AuditResult) {
        let entry = AuditEntry { operation, capsule_id, timestamp: get_timestamp(), result };
        let mut log = self.audit_log.lock();
        log.push(entry);
        if log.len() > 10000 {
            log.remove(0);
        }
    }
}
