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

use alloc::string::String;
use super::types::Capability;

#[derive(Debug, Clone)]
pub struct SecurityViolation {
    pub timestamp: u64,
    pub process_id: u64,
    pub chamber_id: Option<u64>,
    pub violation_type: ViolationType,
    pub attempted_capability: Option<Capability>,
    pub severity: ViolationSeverity,
    pub context: String,
}

#[derive(Debug, Clone)]
pub enum ViolationType {
    UnauthorizedCapabilityUse,
    CapabilityExpired,
    ExcessiveDelegation,
    MemoryViolation,
    QuantumDecoherence,
    AttestationFailure,
    ChamberBreach,
    EphemeralKeyCompromise,
}

#[derive(Debug, Clone)]
pub enum ViolationSeverity {
    Low,
    Medium,
    High,
    Critical,
    Emergency,
}
