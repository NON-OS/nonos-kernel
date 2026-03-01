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

use crate::security::{policy, monitoring, quantum, network};

#[derive(Debug)]
pub struct SecurityStats {
    pub advanced: policy::advanced::SecurityStats,
    pub monitor: monitoring::monitor::MonitorStats,
    pub quantum: quantum::pqc::QuantumSecurityStats,
    pub zkids: network::zkids::ZkidsStats,
}

pub fn get_security_stats() -> SecurityStats {
    SecurityStats {
        advanced: policy::advanced::security_manager().stats(),
        monitor: monitoring::monitor::get_stats(),
        quantum: quantum::pqc::QuantumSecurityStats {
            key_count: 0,
            compliance_events: 0,
            qkd_count: 0,
            entropy_bits: 0.0,
            threat_detections: 0,
            trust_verifications: 0,
        },
        zkids: network::zkids::get_zkids_stats(),
    }
}
