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

#[derive(Clone)]
pub struct AgentContext {
    pub agent_id: u32,
    pub working_dir: Vec<u8>,
    pub env_vars: Vec<(Vec<u8>, Vec<u8>)>,
    pub history: Vec<Vec<u8>>,
    pub active_tools: [bool; 16],
}

impl AgentContext {
    pub fn new(agent_id: u32) -> Self {
        Self {
            agent_id,
            working_dir: b"/ram".to_vec(),
            env_vars: Vec::new(),
            history: Vec::new(),
            active_tools: [false; 16],
        }
    }

    pub fn set_env(&mut self, key: &[u8], value: &[u8]) {
        if let Some(e) = self.env_vars.iter_mut().find(|(k, _)| k == key) {
            e.1 = value.to_vec();
        } else {
            self.env_vars.push((key.to_vec(), value.to_vec()));
        }
    }

    pub fn get_env(&self, key: &[u8]) -> Option<&[u8]> {
        self.env_vars.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_slice())
    }

    pub fn add_history(&mut self, entry: &[u8]) {
        self.history.push(entry.to_vec());
        if self.history.len() > 100 {
            self.history.remove(0);
        }
    }

    pub fn enable_tool(&mut self, idx: usize) {
        if idx < 16 {
            self.active_tools[idx] = true;
        }
    }
    pub fn disable_tool(&mut self, idx: usize) {
        if idx < 16 {
            self.active_tools[idx] = false;
        }
    }
    pub fn is_tool_enabled(&self, idx: usize) -> bool {
        idx < 16 && self.active_tools[idx]
    }
}
