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

pub mod audit;
pub mod engine;
pub mod pq_ops;
pub mod rng;
pub mod threat;
pub mod types;
pub mod vault;
pub mod zerotrust;

pub use audit::QuantumAuditLog;
pub use engine::QuantumSecurityEngine;
pub use rng::QuantumRng;
pub use threat::KernelThreatAI;
pub use types::{
    QuantumAlgorithm, QuantumAuditEvent, QuantumKey, QuantumKeyRotation, QuantumKeyRotationPolicy,
    QuantumSecurityStats, ThreatDetectionEngine,
};
pub use vault::QuantumKeyVault;
pub use zerotrust::QuantumZeroTrust;
