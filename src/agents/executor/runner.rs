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

use crate::agents::core::{AgentState, MessageRole};
use crate::agents::registry::{get_agent, with_agent_mut};
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

pub(super) fn execute_loop(agent_id: u32) {
    const MAX_ITERATIONS: u8 = 8;
    for _ in 0..MAX_ITERATIONS {
        let agent_data = match get_agent(agent_id) {
            Some(a) => a,
            None => break,
        };
        let response = crate::agents::llm::generate(&agent_data.messages, &agent_data.config);
        with_agent_mut(agent_id, |agent| {
            agent.add_message(MessageRole::Assistant, &response);
        });
        if let Some((name, args)) = parse_tool_call(&response) {
            let result = crate::agents::tools::execute_tool(&name, &args);
            with_agent_mut(agent_id, |agent| {
                agent.add_message(MessageRole::Tool, &result);
            });
            continue;
        }
        with_agent_mut(agent_id, |agent| {
            agent.output = response;
            agent.state = AgentState::Complete;
        });
        break;
    }
    super::EXECUTION_FLAG.store(false, Ordering::Relaxed);
}

fn parse_tool_call(response: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let s = core::str::from_utf8(response).ok()?;
    if !s.contains("<tool>") {
        return None;
    }
    let start = s.find("<tool>")? + 6;
    let end = s.find("</tool>")?;
    let inner = s[start..end].trim();
    let name_end = inner.find(' ').unwrap_or(inner.len());
    let name = inner[..name_end].as_bytes().to_vec();
    let args = if name_end < inner.len() {
        inner[name_end..].trim().as_bytes().to_vec()
    } else {
        Vec::new()
    };
    Some((name, args))
}
