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

use alloc::vec::Vec;
use super::core::{AgentMessage, AgentConfig, MessageRole};

pub(super) fn generate(messages: &[AgentMessage], config: &AgentConfig) -> Vec<u8> {
    let prompt = build_prompt(messages, config);
    inference(&prompt, config.max_tokens, config.temperature)
}

fn build_prompt(messages: &[AgentMessage], config: &AgentConfig) -> Vec<u8> {
    let mut prompt = Vec::new();
    if !config.system_prompt.is_empty() {
        prompt.extend_from_slice(b"<system>");
        prompt.extend_from_slice(&config.system_prompt);
        prompt.extend_from_slice(b"</system>\n");
    }
    for m in messages {
        let tag: &[u8] = match m.role {
            MessageRole::User => b"user",
            MessageRole::Assistant => b"assistant",
            MessageRole::Tool => b"tool",
            MessageRole::System => b"system",
        };
        prompt.push(b'<');
        prompt.extend_from_slice(tag);
        prompt.push(b'>');
        prompt.extend_from_slice(&m.content);
        prompt.extend_from_slice(b"</");
        prompt.extend_from_slice(tag);
        prompt.extend_from_slice(b">\n");
    }
    prompt
}

fn inference(_prompt: &[u8], _max_tokens: u32, _temp: u8) -> Vec<u8> {
    b"I understand your request. Let me help you with that.".to_vec()
}
