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

use super::task::Task;
use super::deadline_types::DeadlineFlags;

impl Task {
    pub fn run(&mut self) {
        let start = crate::sys::clock::get_ticks();
        self.exec_start = start;
        if let Some(func) = self.func {
            func();
        } else if self.entry_point != 0 {
            unsafe {
                let entry: extern "C" fn() = core::mem::transmute(self.entry_point as usize);
                entry();
            }
        }
        let elapsed = crate::sys::clock::get_ticks().saturating_sub(start);
        self.sum_exec_runtime = self.sum_exec_runtime.saturating_add(elapsed);
        if let Some(ref mut dl) = self.deadline_params {
            dl.remaining_runtime = dl.remaining_runtime.saturating_sub(elapsed);
            if dl.remaining_runtime == 0 { dl.flags |= DeadlineFlags::THROTTLED; }
        }
        self.complete = true;
    }

    pub fn has_missed_deadline(&self) -> bool {
        if let Some(ref dl) = self.deadline_params {
            let now = crate::sys::clock::get_ticks();
            now > dl.abs_deadline && !self.complete
        } else { false }
    }

    pub fn replenish_deadline(&mut self) {
        if let Some(ref mut dl) = self.deadline_params {
            let now = crate::sys::clock::get_ticks();
            dl.period_start = now;
            dl.abs_deadline = now + dl.deadline;
            dl.remaining_runtime = dl.runtime;
            dl.flags.remove(DeadlineFlags::THROTTLED);
            dl.flags.insert(DeadlineFlags::DL_NEW);
        }
    }
}
