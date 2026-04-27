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

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use spin::RwLock;

struct SocketRegistry {
    sockets: BTreeMap<u64, Vec<usize>>,
}
static REG: RwLock<Option<SocketRegistry>> = RwLock::new(None);

pub fn init() {
    *REG.write() = Some(SocketRegistry { sockets: BTreeMap::new() });
}

pub fn register_socket(pid: u64, socket_id: usize) {
    if let Some(r) = REG.write().as_mut() {
        r.sockets.entry(pid).or_insert_with(Vec::new).push(socket_id);
    }
}

pub fn unregister_socket(pid: u64, socket_id: usize) {
    if let Some(r) = REG.write().as_mut() {
        if let Some(socks) = r.sockets.get_mut(&pid) {
            socks.retain(|&s| s != socket_id);
        }
    }
}

pub fn close_all_for_pid(pid: u64) {
    if let Some(r) = REG.write().as_mut() {
        if let Some(socks) = r.sockets.remove(&pid) {
            for sock_id in socks {
                close_socket(sock_id);
            }
        }
    }
}

pub fn get_sockets_for_pid(pid: u64) -> Vec<usize> {
    REG.read().as_ref().and_then(|r| r.sockets.get(&pid).cloned()).unwrap_or_default()
}

fn close_socket(socket_id: usize) {
    if let Some(stack) = crate::network::get_network_stack() {
        stack.close_socket(socket_id);
    }
}

pub fn socket_count() -> usize {
    REG.read().as_ref().map(|r| r.sockets.values().map(|v| v.len()).sum()).unwrap_or(0)
}
