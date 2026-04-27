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

mod apps;
mod filesystem;
mod system;
mod wallet;

use alloc::format;
use alloc::vec::Vec;
use spin::Mutex;

pub const MAX_TOOLS: usize = 32;
pub type ToolFn = fn(&[u8]) -> Vec<u8>;

#[derive(Clone, Copy)]
pub struct Tool {
    pub name: [u8; 32],
    pub description: [u8; 128],
    pub handler: ToolFn,
}

static TOOLS: Mutex<[Option<Tool>; MAX_TOOLS]> = Mutex::new([None; MAX_TOOLS]);

pub fn register_tool(name: &[u8], desc: &[u8], handler: ToolFn) -> bool {
    let mut n = [0u8; 32];
    let mut d = [0u8; 128];
    n[..name.len().min(32)].copy_from_slice(&name[..name.len().min(32)]);
    d[..desc.len().min(128)].copy_from_slice(&desc[..desc.len().min(128)]);
    let tool = Tool { name: n, description: d, handler };
    let mut tools = TOOLS.lock();
    for slot in tools.iter_mut() {
        if slot.is_none() {
            *slot = Some(tool);
            return true;
        }
    }
    false
}

pub fn execute_tool(name: &[u8], args: &[u8]) -> Vec<u8> {
    let tools = TOOLS.lock();
    for t in tools.iter().flatten() {
        let len = t.name.iter().position(|&c| c == 0).unwrap_or(32);
        if &t.name[..len] == name {
            return (t.handler)(args);
        }
    }
    format!("Tool '{}' not found", core::str::from_utf8(name).unwrap_or("?")).into_bytes()
}

pub fn list_tools() -> Vec<([u8; 32], [u8; 128])> {
    TOOLS.lock().iter().flatten().map(|t| (t.name, t.description)).collect()
}

pub fn init_builtin_tools() {
    filesystem::register();
    system::register();
    wallet::register();
    apps::register();
}
