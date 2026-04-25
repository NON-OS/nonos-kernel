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

mod extract;
mod process;
mod response;

use super::core::{AgentConfig, AgentMessage, MessageRole};
use alloc::vec::Vec;

pub(super) fn generate(messages: &[AgentMessage], config: &AgentConfig) -> Vec<u8> {
    let last_user = messages.iter().rev().find(|m| m.role == MessageRole::User);
    let last_tool = messages.iter().rev().find(|m| m.role == MessageRole::Tool);
    if let Some(tool_msg) = last_tool {
        if messages.last().map(|m| m.role == MessageRole::Tool).unwrap_or(false) {
            return response::format_tool_response(&tool_msg.content, config);
        }
    }
    if let Some(user_msg) = last_user {
        return process::process_user_request(&user_msg.content, config);
    }
    b"How can I help you?".to_vec()
}
