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
pub struct IsolationPolicy {
    pub inbox_capacity: usize,
    pub max_msg_bytes: usize,
    pub max_bytes_per_sec: u64,
    pub heartbeat_interval_ms: u64,
}

impl Default for IsolationPolicy {
    fn default() -> Self {
        Self {
            inbox_capacity: 1024,
            max_msg_bytes: 1 << 20,
            max_bytes_per_sec: 4 << 20,
            heartbeat_interval_ms: 2_000,
        }
    }
}
