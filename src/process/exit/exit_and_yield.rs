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

//! Tear the current capsule down and yield until the scheduler
//! picks another pid. Called from `MkExit`, the signal-kill default
//! action, and the CPL=3 fault handlers — every site where the
//! capsule's user address space is gone and an iretq has nowhere to
//! land.

use super::teardown::teardown;
use crate::process::current_pid;

pub fn exit_and_yield(exit_code: i32, by_signal: bool) -> ! {
    if let Some(pid) = current_pid() {
        teardown(pid, exit_code, by_signal);
    }
    loop {
        crate::sched::yield_now();
    }
}
