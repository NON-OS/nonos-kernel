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

mod types;
mod isolation;
mod attestation;
mod quantum;
mod violations;
mod stats;
mod engine;
mod api;

pub use types::{Capability, CapabilityType, CapabilitySet};
pub use isolation::{IsolationLevel, IsolationChamber, SealedMemoryRegion, ExecutionContext};
pub use attestation::AttestationLink;
pub use quantum::{QuantumState, QuantumParticle};
pub use violations::{SecurityViolation, ViolationType, ViolationSeverity};
pub use stats::ChamberStats;
pub use engine::CapabilityEngine;
pub use api::{
    init_capability_system,
    init_capability_engine,
    get_capability_engine,
    create_isolation_chamber,
    enter_chamber,
    check_capability,
    get_secure_random_bytes,
    init_capabilities,
};
