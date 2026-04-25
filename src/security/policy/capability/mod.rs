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

mod api;
mod attestation;
mod engine;
mod isolation;
mod quantum;
mod stats;
mod types;
mod violations;

pub use api::{
    check_capability, create_isolation_chamber, enter_chamber, get_capability_engine,
    get_secure_random_bytes, init_capabilities, init_capability_engine, init_capability_system,
};
pub use attestation::AttestationLink;
pub use engine::CapabilityEngine;
pub use isolation::{ExecutionContext, IsolationChamber, IsolationLevel, SealedMemoryRegion};
pub use quantum::{QuantumParticle, QuantumState};
pub use stats::ChamberStats;
pub use types::{Capability, CapabilitySet, CapabilityType};
pub use violations::{SecurityViolation, ViolationSeverity, ViolationType};

pub fn has_capability(pid: u32, cap_bits: u64) -> bool {
    let engine = match get_capability_engine() {
        Some(e) => e,
        None => return false,
    };
    let caps = [
        Capability::ProcessCreate,
        Capability::ProcessKill,
        Capability::MemoryMap,
        Capability::MemoryUnmap,
        Capability::FileRead,
        Capability::FileWrite,
        Capability::FileCreate,
        Capability::FileDelete,
        Capability::NetworkBind,
        Capability::NetworkConnect,
        Capability::DeviceAccess,
        Capability::SystemCall,
    ];
    for cap in caps {
        if (cap_bits & (cap as u64)) != 0
            && !engine.check_capability(pid as u64, cap).unwrap_or(false)
        {
            return false;
        }
    }
    true
}
