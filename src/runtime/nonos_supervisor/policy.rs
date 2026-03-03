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
pub struct SupervisorPolicy {
    pub restart_on_degraded: bool,
    pub restart_on_stopped: bool,
    pub restart_cooldown_ms: u64,
    pub max_restarts_per_minute: u32,
}

impl Default for SupervisorPolicy {
    fn default() -> Self {
        Self {
            restart_on_degraded: true,
            restart_on_stopped: true,
            restart_cooldown_ms: 5_000,
            max_restarts_per_minute: 10,
        }
    }
}
