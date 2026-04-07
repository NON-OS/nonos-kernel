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

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, Default)]
    pub struct DeadlineFlags: u32 {
        const RESET_ON_FORK = 1 << 0;
        const RECLAIM = 1 << 1;
        const THROTTLED = 1 << 2;
        const DL_OVERRUN = 1 << 3;
        const DL_NEW = 1 << 4;
        const DL_BOOSTED = 1 << 5;
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DeadlineParams {
    pub runtime: u64,
    pub deadline: u64,
    pub period: u64,
    pub abs_deadline: u64,
    pub remaining_runtime: u64,
    pub period_start: u64,
    pub deadline_misses: u64,
    pub flags: DeadlineFlags,
}

impl DeadlineParams {
    pub fn new(runtime: u64, deadline: u64, period: u64) -> Self {
        Self {
            runtime, deadline,
            period: if period == 0 { deadline } else { period },
            abs_deadline: 0, remaining_runtime: runtime, period_start: 0,
            deadline_misses: 0, flags: DeadlineFlags::empty(),
        }
    }

    pub fn is_valid(&self) -> bool {
        self.runtime > 0 && self.deadline > 0 && self.period > 0
            && self.runtime <= self.deadline && self.deadline <= self.period
    }

    pub fn bandwidth(&self) -> u64 {
        if self.period == 0 { return 0; }
        (self.runtime << 20) / self.period
    }
}
