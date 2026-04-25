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

#[derive(Clone, Copy, PartialEq)]
pub enum AgentState {
    Idle,
    Running,
    Paused,
    Error,
    Complete,
}

#[derive(Clone)]
pub struct AgentMessage {
    pub role: MessageRole,
    pub content: Vec<u8>,
}

#[derive(Clone, Copy, PartialEq)]
pub enum MessageRole {
    System,
    User,
    Assistant,
    Tool,
}

#[derive(Clone)]
pub struct AgentConfig {
    pub name: [u8; 32],
    pub system_prompt: Vec<u8>,
    pub max_tokens: u32,
    pub temperature: u8,
    pub tools_enabled: [bool; 16],
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            name: [0; 32],
            system_prompt: Vec::new(),
            max_tokens: 4096,
            temperature: 70,
            tools_enabled: [false; 16],
        }
    }
}

#[derive(Clone)]
pub struct Agent {
    pub id: u32,
    pub config: AgentConfig,
    pub state: AgentState,
    pub messages: Vec<AgentMessage>,
    pub output: Vec<u8>,
    pub created_at: u64,
    pub last_run: u64,
}

impl Agent {
    pub fn new(id: u32, config: AgentConfig) -> Self {
        #[cfg(test)]
        let now = 1000u64;
        #[cfg(not(test))]
        let now = crate::time::timestamp_millis();
        Self {
            id,
            config,
            state: AgentState::Idle,
            messages: Vec::new(),
            output: Vec::new(),
            created_at: now,
            last_run: 0,
        }
    }

    pub fn add_message(&mut self, role: MessageRole, content: &[u8]) {
        self.messages.push(AgentMessage { role, content: content.to_vec() });
    }

    pub fn clear_messages(&mut self) {
        self.messages.clear();
    }

    pub fn name(&self) -> &[u8] {
        let len = self.config.name.iter().position(|&c| c == 0).unwrap_or(32);
        &self.config.name[..len]
    }
}
