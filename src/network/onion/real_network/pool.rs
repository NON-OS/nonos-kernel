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


use alloc::{collections::BTreeMap, vec::Vec};
use spin::Mutex;
use crate::network::ip::IpAddress;
use super::types::ConnectionState;
use super::connection::AnyoneConnection;

pub(super) struct ConnectionPool {
    buckets: Mutex<BTreeMap<(IpAddress, u16), Vec<AnyoneConnection>>>,
    max_pool_size: usize,
    max_idle_ms: u64,
}

impl ConnectionPool {
    pub(super) fn new(max_pool_size: usize, max_idle_ms: u64) -> Self {
        Self {
            buckets: Mutex::new(BTreeMap::new()),
            max_pool_size,
            max_idle_ms,
        }
    }

    pub(super) fn take(&self, addr: &IpAddress, port: u16, now_ms: u64) -> Option<AnyoneConnection> {
        let mut buckets = self.buckets.lock();
        if let Some(vec) = buckets.get_mut(&(*addr, port)) {
            while let Some(c) = vec.pop() {
                if now_ms.saturating_sub(c.last_activity_ms) > self.max_idle_ms
                    || matches!(c.state, ConnectionState::Closed | ConnectionState::Error)
                {
                    continue;
                }
                return Some(c);
            }
        }
        None
    }

    pub(super) fn put(&self, conn: AnyoneConnection) {
        if !matches!(conn.state, ConnectionState::Authenticated) {
            return;
        }
        let key = (conn.remote_addr, conn.remote_port);
        let mut buckets = self.buckets.lock();
        let entry = buckets.entry(key).or_insert_with(Vec::new);
        if entry.len() < self.max_pool_size {
            entry.push(conn);
        }
    }

    pub(super) fn evict_idle(&self, now_ms: u64) {
        let mut buckets = self.buckets.lock();
        let keys: Vec<(IpAddress, u16)> = buckets.keys().copied().collect();
        for k in keys {
            if let Some(v) = buckets.get_mut(&k) {
                v.retain(|c| {
                    (now_ms.saturating_sub(c.last_activity_ms) <= self.max_idle_ms)
                        && !matches!(c.state, ConnectionState::Closed | ConnectionState::Error)
                });
            }
        }
    }
}
