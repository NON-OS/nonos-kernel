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

use super::scheduler;

pub fn current_scheduler() -> Option<&'static scheduler::Scheduler> {
    scheduler::get()
}

pub fn yield_cpu() {
    scheduler::yield_now();
}

#[inline]
pub fn schedule() {
    scheduler::run();
}

pub fn current_cpu_id() -> u32 {
    crate::arch::x86_64::cpu::current_cpu_id() as u32
}
