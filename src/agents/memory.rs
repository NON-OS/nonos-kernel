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
use spin::Mutex;

pub const MAX_ENTRIES: usize = 1024;

#[derive(Clone)]
pub struct MemoryEntry {
    pub key: [u8; 64],
    pub value: Vec<u8>,
    pub agent_id: u32,
    pub timestamp: u64,
    pub importance: u8,
}

static MEMORY: Mutex<Vec<MemoryEntry>> = Mutex::new(Vec::new());

pub struct AgentMemory {
    pub agent_id: u32,
}

impl AgentMemory {
    pub fn new(agent_id: u32) -> Self {
        Self { agent_id }
    }

    pub fn store(&self, key: &[u8], value: &[u8], importance: u8) {
        let mut k = [0u8; 64];
        let len = key.len().min(64);
        k[..len].copy_from_slice(&key[..len]);
        let entry = MemoryEntry {
            key: k,
            value: value.to_vec(),
            agent_id: self.agent_id,
            timestamp: crate::time::timestamp_millis(),
            importance,
        };
        let mut mem = MEMORY.lock();
        if let Some(e) =
            mem.iter_mut().find(|e| e.agent_id == self.agent_id && e.key[..len] == k[..len])
        {
            e.value = value.to_vec();
            e.timestamp = entry.timestamp;
            return;
        }
        if mem.len() >= MAX_ENTRIES {
            mem.remove(0);
        }
        mem.push(entry);
    }

    pub fn recall(&self, key: &[u8]) -> Option<Vec<u8>> {
        let mut k = [0u8; 64];
        let len = key.len().min(64);
        k[..len].copy_from_slice(&key[..len]);
        let mem = MEMORY.lock();
        mem.iter()
            .find(|e| e.agent_id == self.agent_id && e.key[..len] == k[..len])
            .map(|e| e.value.clone())
    }

    pub fn search(&self, query: &[u8]) -> Vec<MemoryEntry> {
        let mem = MEMORY.lock();
        mem.iter()
            .filter(|e| e.agent_id == self.agent_id && contains(&e.value, query))
            .cloned()
            .collect()
    }

    pub fn recent(&self, count: usize) -> Vec<MemoryEntry> {
        let mem = MEMORY.lock();
        let mut entries: Vec<_> =
            mem.iter().filter(|e| e.agent_id == self.agent_id).cloned().collect();
        entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        entries.truncate(count);
        entries
    }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    needle.is_empty() || hay.windows(needle.len()).any(|w| w == needle)
}
