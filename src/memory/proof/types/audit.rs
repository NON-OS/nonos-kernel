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

use super::tags::{AuditOperation, AuditResult};

#[derive(Debug)]
pub struct ProofStats {
    pub total_capsules: usize,
    pub total_proofs: usize,
    pub audit_entries: usize,
}

#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub operation: AuditOperation,
    pub capsule_id: u64,
    pub timestamp: u64,
    pub result: AuditResult,
}
