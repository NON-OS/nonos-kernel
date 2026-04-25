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

use super::core::{Agent, AgentConfig};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use spin::Mutex;

pub const MAX_AGENTS: usize = 32;

static AGENTS: Mutex<Vec<Agent>> = Mutex::new(Vec::new());
static NEXT_ID: AtomicU32 = AtomicU32::new(1);

pub fn create_agent(config: AgentConfig) -> u32 {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let agent = Agent::new(id, config);
    let mut agents = AGENTS.lock();
    if agents.len() < MAX_AGENTS {
        agents.push(agent);
    }
    id
}

pub fn get_agent(id: u32) -> Option<Agent> {
    let agents = AGENTS.lock();
    agents.iter().find(|a| a.id == id).cloned()
}

pub fn with_agent_mut<F, R>(id: u32, f: F) -> Option<R>
where
    F: FnOnce(&mut Agent) -> R,
{
    let mut agents = AGENTS.lock();
    agents.iter_mut().find(|a| a.id == id).map(f)
}

pub fn update_agent<F>(id: u32, f: F) -> bool
where
    F: FnOnce(&mut Agent),
{
    let mut agents = AGENTS.lock();
    if let Some(agent) = agents.iter_mut().find(|a| a.id == id) {
        f(agent);
        true
    } else {
        false
    }
}

pub fn list_agents() -> Vec<(u32, [u8; 32])> {
    let agents = AGENTS.lock();
    agents.iter().map(|a| (a.id, a.config.name)).collect()
}

pub fn delete_agent(id: u32) -> bool {
    let mut agents = AGENTS.lock();
    let before = agents.len();
    agents.retain(|a| a.id != id);
    agents.len() < before
}

pub fn agent_count() -> usize {
    AGENTS.lock().len()
}
