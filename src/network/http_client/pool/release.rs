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

use super::helpers::{close_connection, evict_oldest_global, pool_key};
use super::types::{
    ConnectionPool, PooledConnection, MAX_PER_HOST, MAX_REQUESTS_PER_CONN, MAX_TOTAL,
};
use alloc::vec::Vec;

impl ConnectionPool {
    pub(in crate::network::http_client) fn release(
        &self,
        host: &str,
        port: u16,
        mut conn: PooledConnection,
        keep_alive: bool,
    ) {
        if !keep_alive || conn.request_count >= MAX_REQUESTS_PER_CONN {
            close_connection(conn);
            return;
        }
        conn.last_used_ms = crate::time::timestamp_millis();
        let key = pool_key(host, port, conn.is_tls);
        let mut map = self.entries.lock();
        let total: usize = map.values().map(|v| v.len()).sum();
        if total >= MAX_TOTAL {
            if !evict_oldest_global(&mut map) {
                drop(map);
                close_connection(conn);
                return;
            }
        }
        let conns = map.entry(key).or_insert_with(Vec::new);
        if conns.len() >= MAX_PER_HOST {
            if let Some(oldest) = conns.iter().enumerate().min_by_key(|(_, c)| c.last_used_ms) {
                let idx = oldest.0;
                let evicted = conns.remove(idx);
                if let Some(stack) = crate::network::stack::get_network_stack() {
                    let _ = stack.tcp_close(evicted.conn_id);
                }
            }
        }
        conns.push(conn);
    }
}
