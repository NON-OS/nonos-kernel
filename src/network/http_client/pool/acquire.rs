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

use super::helpers::{evict_stale_vec, pool_key};
use super::types::{ConnectionPool, PooledConnection};
use alloc::vec::Vec;

impl ConnectionPool {
    pub(in crate::network::http_client) fn acquire(
        &self,
        host: &str,
        port: u16,
        is_tls: bool,
    ) -> Option<PooledConnection> {
        let key = pool_key(host, port, is_tls);
        let now_ms = crate::time::timestamp_millis();
        let mut map = self.entries.lock();
        if let Some(conns) = map.get_mut(&key) {
            evict_stale_vec(conns, now_ms);
        }
        let conns = map.get_mut(&key)?;
        if conns.is_empty() {
            map.remove(&key);
            return None;
        }
        let stack = crate::network::stack::get_network_stack()?;
        let idx = conns.iter().position(|c| match stack.tcp_is_closed(c.conn_id) {
            Some(false) => true,
            _ => false,
        });
        match idx {
            Some(i) => {
                let conn = conns.remove(i);
                if conns.is_empty() {
                    map.remove(&key);
                }
                Some(conn)
            }
            None => {
                let dead: Vec<u32> = conns.iter().map(|c| c.conn_id).collect();
                conns.clear();
                map.remove(&key);
                for id in dead {
                    let _ = stack.tcp_close(id);
                }
                None
            }
        }
    }
}
