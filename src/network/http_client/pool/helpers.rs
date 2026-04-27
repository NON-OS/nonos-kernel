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

use super::types::{PooledConnection, IDLE_TIMEOUT_MS};
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

pub(super) fn pool_key(host: &str, port: u16, is_tls: bool) -> String {
    if is_tls {
        format!("{}:{}:tls", host, port)
    } else {
        format!("{}:{}", host, port)
    }
}

pub(super) fn evict_stale_vec(conns: &mut Vec<PooledConnection>, now_ms: u64) {
    let stack = crate::network::stack::get_network_stack();
    conns.retain(|c| {
        let age_ms = now_ms.saturating_sub(c.last_used_ms);
        if age_ms > IDLE_TIMEOUT_MS {
            if let Some(ref s) = stack {
                let _ = s.tcp_close(c.conn_id);
            }
            false
        } else {
            true
        }
    });
}

pub(super) fn evict_oldest_global(map: &mut BTreeMap<String, Vec<PooledConnection>>) -> bool {
    let mut oldest_key: Option<String> = None;
    let mut oldest_idx: usize = 0;
    let mut oldest_time: u64 = u64::MAX;
    let mut oldest_conn_id: u32 = 0;
    for (key, conns) in map.iter() {
        for (i, c) in conns.iter().enumerate() {
            if c.last_used_ms < oldest_time {
                oldest_time = c.last_used_ms;
                oldest_key = Some(key.clone());
                oldest_idx = i;
                oldest_conn_id = c.conn_id;
            }
        }
    }
    if let Some(key) = oldest_key {
        if let Some(conns) = map.get_mut(&key) {
            conns.remove(oldest_idx);
            if conns.is_empty() {
                map.remove(&key);
            }
        }
        if let Some(stack) = crate::network::stack::get_network_stack() {
            let _ = stack.tcp_close(oldest_conn_id);
        }
        true
    } else {
        false
    }
}

pub(super) fn close_connection(conn: PooledConnection) {
    if let Some(stack) = crate::network::stack::get_network_stack() {
        let _ = stack.tcp_close(conn.conn_id);
    }
}
