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

use core::sync::atomic::{AtomicU32, AtomicBool, Ordering};
use alloc::vec::Vec;
use super::core::{AgentState, MessageRole};
use super::registry::get_agent_mut;

static RUNNING_AGENT: AtomicU32 = AtomicU32::new(0);
static EXECUTION_FLAG: AtomicBool = AtomicBool::new(false);

pub fn run_agent(agent_id: u32, input: &[u8]) -> bool {
    if EXECUTION_FLAG.load(Ordering::Relaxed) { return false; }
    let agent = match get_agent_mut(agent_id) { Some(a) => a, None => return false };
    agent.state = AgentState::Running;
    agent.last_run = crate::time::timestamp_millis();
    agent.add_message(MessageRole::User, input);
    RUNNING_AGENT.store(agent_id, Ordering::Relaxed);
    EXECUTION_FLAG.store(true, Ordering::Relaxed);
    execute_step(agent_id);
    true
}

fn execute_step(agent_id: u32) {
    let agent = match get_agent_mut(agent_id) { Some(a) => a, None => return };
    let response = super::llm::generate(&agent.messages, &agent.config);
    agent.add_message(MessageRole::Assistant, &response);
    if let Some(tool_call) = parse_tool_call(&response) {
        let result = super::tools::execute_tool(&tool_call.0, &tool_call.1);
        agent.add_message(MessageRole::Tool, &result);
        return;
    }
    agent.output = response;
    agent.state = AgentState::Complete;
    EXECUTION_FLAG.store(false, Ordering::Relaxed);
}

fn parse_tool_call(response: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let s = core::str::from_utf8(response).ok()?;
    if !s.contains("<tool>") { return None; }
    let start = s.find("<tool>")? + 6;
    let end = s.find("</tool>")?;
    let name_end = s[start..end].find(' ').unwrap_or(end - start);
    let name = s[start..start + name_end].as_bytes().to_vec();
    let args = s[start + name_end..end].trim().as_bytes().to_vec();
    Some((name, args))
}

pub fn stop_agent(agent_id: u32) {
    if let Some(a) = get_agent_mut(agent_id) { a.state = AgentState::Idle; }
    EXECUTION_FLAG.store(false, Ordering::Relaxed);
}

pub fn agent_output(agent_id: u32) -> Vec<u8> {
    super::registry::get_agent(agent_id).map(|a| a.output.clone()).unwrap_or_default()
}

pub fn is_running() -> bool { EXECUTION_FLAG.load(Ordering::Relaxed) }
