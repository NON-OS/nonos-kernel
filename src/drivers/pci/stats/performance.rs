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

#[derive(Debug, Clone)]
pub struct PerformanceMetrics {
    pub avg_config_read_ns: u64,
    pub avg_config_write_ns: u64,
    pub enumeration_throughput: f64,
    pub interrupt_rate_per_sec: f64,
}

impl PerformanceMetrics {
    pub fn new() -> Self {
        Self {
            avg_config_read_ns: 0,
            avg_config_write_ns: 0,
            enumeration_throughput: 0.0,
            interrupt_rate_per_sec: 0.0,
        }
    }
}

impl Default for PerformanceMetrics {
    fn default() -> Self {
        Self::new()
    }
}
