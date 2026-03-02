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

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::Ordering;
use super::error::{RunnerError, RunnerResult};
use super::types::ExecutionState;
use super::executor::{CONTEXTS, stop_module, RUNNING_COUNT};
use super::helpers::get_current_time;

pub fn get_running_count() -> u64 {
    RUNNING_COUNT.load(Ordering::SeqCst)
}

pub fn heartbeat(module_id: u64) -> RunnerResult<()> {
    let mut contexts = CONTEXTS.write();
    let context = contexts.get_mut(&module_id).ok_or(RunnerError::ModuleNotFound)?;
    context.update_heartbeat(get_current_time());
    Ok(())
}

pub fn check_watchdogs() -> Vec<u64> {
    let current_time = get_current_time();
    let mut timed_out = Vec::new();

    let contexts = CONTEXTS.read();
    for (module_id, context) in contexts.iter() {
        if context.state == ExecutionState::Running && !context.check_watchdog(current_time) {
            timed_out.push(*module_id);
        }
    }

    timed_out
}

pub fn terminate_all_modules() {
    let module_ids: Vec<u64> = {
        let contexts = CONTEXTS.read();
        contexts.keys().copied().collect()
    };

    for module_id in module_ids {
        stop_module(module_id).ok();
    }
}
