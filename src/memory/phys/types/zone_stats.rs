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

#[derive(Clone, Copy, Debug, Default)]
pub struct ZoneStats {
    pub frames_total: usize,
    pub frames_free: usize,
}

impl ZoneStats {
    pub const fn new(total: usize, free: usize) -> Self {
        Self { frames_total: total, frames_free: free }
    }

    pub const fn frames_allocated(&self) -> usize {
        self.frames_total.saturating_sub(self.frames_free)
    }

    pub const fn usage_percent(&self) -> usize {
        if self.frames_total == 0 {
            return 0;
        }
        (self.frames_allocated() * 100) / self.frames_total
    }

    pub const fn total_bytes(&self, page_size: usize) -> usize {
        self.frames_total.saturating_mul(page_size)
    }

    pub const fn free_bytes(&self, page_size: usize) -> usize {
        self.frames_free.saturating_mul(page_size)
    }
}
