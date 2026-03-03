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
pub struct RestartWindow {
    pub(super) window_start_ms: u64,
    pub(super) count: u32,
    pub(super) last_restart_ms: u64,
}

impl RestartWindow {
    pub fn new(now: u64) -> Self {
        Self {
            window_start_ms: now,
            count: 0,
            last_restart_ms: 0,
        }
    }

    pub fn can_restart(&mut self, now: u64, cooldown_ms: u64, max_per_minute: u32) -> bool {
        if self.last_restart_ms != 0 && now.saturating_sub(self.last_restart_ms) < cooldown_ms {
            return false;
        }
        if now.saturating_sub(self.window_start_ms) >= 60_000 {
            self.window_start_ms = now;
            self.count = 0;
        }
        if self.count >= max_per_minute {
            return false;
        }
        true
    }

    pub fn mark(&mut self, now: u64) {
        self.count = self.count.saturating_add(1);
        self.last_restart_ms = now;
    }
}
