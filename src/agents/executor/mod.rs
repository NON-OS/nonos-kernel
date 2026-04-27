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

mod runner;

use super::core::{AgentState, MessageRole};
use super::registry::{update_agent, with_agent_mut};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

pub(super) static RUNNING_AGENT: AtomicU32 = AtomicU32::new(0);
pub(super) static EXECUTION_FLAG: AtomicBool = AtomicBool::new(false);

pub fn run_agent(agent_id: u32, input: &[u8]) -> bool {
    if EXECUTION_FLAG.load(Ordering::Relaxed) {
        return false;
    }
    let setup_ok = with_agent_mut(agent_id, |agent| {
        agent.state = AgentState::Running;
        agent.last_run = crate::time::timestamp_millis();
        agent.add_message(MessageRole::User, input);
    });
    if setup_ok.is_none() {
        return false;
    }
    RUNNING_AGENT.store(agent_id, Ordering::Relaxed);
    EXECUTION_FLAG.store(true, Ordering::Relaxed);
    runner::execute_loop(agent_id);
    true
}

pub fn stop_agent(agent_id: u32) {
    update_agent(agent_id, |a| a.state = AgentState::Idle);
    EXECUTION_FLAG.store(false, Ordering::Relaxed);
}

pub fn agent_output(agent_id: u32) -> Vec<u8> {
    super::registry::get_agent(agent_id).map(|a| a.output.clone()).unwrap_or_default()
}

pub fn is_running() -> bool {
    EXECUTION_FLAG.load(Ordering::Relaxed)
}

pub fn current_agent() -> u32 {
    RUNNING_AGENT.load(Ordering::Relaxed)
}
