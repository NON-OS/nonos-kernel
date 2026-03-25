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

//! HTTP connection pool — reuses TCP(+TLS) connections across requests
//! to the same host, eliminating repeated handshake overhead.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;
use spin::Mutex;
use crate::network::onion::tls::TLSConnection;

/// Maximum idle connections per host.
const MAX_PER_HOST: usize = 6;

/// Maximum total idle connections across all hosts.
const MAX_TOTAL: usize = 32;

/// Idle timeout in milliseconds (60 seconds).
const IDLE_TIMEOUT_MS: u64 = 60_000;

/// Maximum number of requests per connection before forced close.
const MAX_REQUESTS_PER_CONN: u32 = 100;

/// A pooled connection holding TCP state and optionally TLS state.
pub(super) struct PooledConnection {
    /// TCP connection ID from the network stack.
    pub conn_id: u32,
    /// TLS connection state (None for plain HTTP).
    pub tls: Option<TLSConnection>,
    /// Timestamp (ms) of last successful use.
    pub last_used_ms: u64,
    /// Number of requests served on this connection.
    pub request_count: u32,
    /// Whether this is a TLS connection.
    pub is_tls: bool,
}

/// Connection pool keyed by `"host:port"`.
pub(super) struct ConnectionPool {
    entries: Mutex<BTreeMap<String, Vec<PooledConnection>>>,
}

impl ConnectionPool {
    pub const fn new() -> Self {
        Self {
            entries: Mutex::new(BTreeMap::new()),
        }
    }

    /// Attempt to acquire an idle connection for the given host and port.
    /// Returns `None` if no healthy idle connection is available.
    /// The returned connection is removed from the pool (single-use checkout).
    pub fn acquire(&self, host: &str, port: u16, is_tls: bool) -> Option<PooledConnection> {
        let key = pool_key(host, port, is_tls);
        let now_ms = crate::time::timestamp_millis();
        let mut map = self.entries.lock();

        // Evict stale connections from this host first
        if let Some(conns) = map.get_mut(&key) {
            evict_stale_vec(conns, now_ms);
        }

        let conns = map.get_mut(&key)?;
        if conns.is_empty() {
            map.remove(&key);
            return None;
        }

        // Find a healthy connection (check via network stack)
        let stack = crate::network::stack::get_network_stack()?;
        let idx = conns.iter().position(|c| {
            // Connection must not be closed at TCP level
            match stack.tcp_is_closed(c.conn_id) {
                Some(false) => true,  // Connection is open
                _ => false,           // Closed or unknown
            }
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
                // All connections are dead, clean up
                let dead: Vec<u32> = conns.iter().map(|c| c.conn_id).collect();
                conns.clear();
                map.remove(&key);
                // Close dead TCP connections outside the lock is ideal,
                // but since we hold Map lock briefly, close them here.
                for id in dead {
                    let _ = stack.tcp_close(id);
                }
                None
            }
        }
    }

    /// Return a connection to the pool for future reuse.
    /// The connection is dropped (not pooled) if:
    /// - `keep_alive` is false (server sent `Connection: close`)
    /// - `request_count` exceeds `MAX_REQUESTS_PER_CONN`
    /// - The pool is at capacity
    pub fn release(&self, host: &str, port: u16, mut conn: PooledConnection, keep_alive: bool) {
        if !keep_alive || conn.request_count >= MAX_REQUESTS_PER_CONN {
            self.close_connection(conn);
            return;
        }

        conn.last_used_ms = crate::time::timestamp_millis();

        let key = pool_key(host, port, conn.is_tls);
        let mut map = self.entries.lock();

        // Count total idle connections
        let total: usize = map.values().map(|v| v.len()).sum();

        // Evict oldest globally if at total capacity
        if total >= MAX_TOTAL {
            if !evict_oldest_global(&mut map) {
                // Pool completely full, drop this connection
                drop(map);
                self.close_connection(conn);
                return;
            }
        }

        let conns = map.entry(key).or_insert_with(Vec::new);

        // Evict oldest per-host if at per-host capacity
        if conns.len() >= MAX_PER_HOST {
            if let Some(oldest) = conns.iter().enumerate().min_by_key(|(_, c)| c.last_used_ms) {
                let idx = oldest.0;
                let evicted = conns.remove(idx);
                // Close evicted connection's TCP
                if let Some(stack) = crate::network::stack::get_network_stack() {
                    let _ = stack.tcp_close(evicted.conn_id);
                }
            }
        }

        conns.push(conn);
    }

    /// Remove all idle connections older than `IDLE_TIMEOUT_MS`.
    /// Called opportunistically from `acquire()` and can be called from a timer.
    pub fn evict_stale(&self) {
        let now_ms = crate::time::timestamp_millis();
        let mut map = self.entries.lock();
        let mut empty_keys = Vec::new();

        for (key, conns) in map.iter_mut() {
            evict_stale_vec(conns, now_ms);
            if conns.is_empty() {
                empty_keys.push(key.clone());
            }
        }

        for key in empty_keys {
            map.remove(&key);
        }
    }

    /// Close all pooled connections and clear the pool.
    pub fn clear(&self) {
        let mut map = self.entries.lock();
        if let Some(stack) = crate::network::stack::get_network_stack() {
            for conns in map.values() {
                for conn in conns {
                    let _ = stack.tcp_close(conn.conn_id);
                }
            }
        }
        map.clear();
    }

    /// Number of idle connections currently in the pool.
    pub fn len(&self) -> usize {
        let map = self.entries.lock();
        map.values().map(|v| v.len()).sum()
    }

    fn close_connection(&self, conn: PooledConnection) {
        if let Some(stack) = crate::network::stack::get_network_stack() {
            let _ = stack.tcp_close(conn.conn_id);
        }
        // TLSConnection Drop will zeroize secrets automatically
    }
}

/// Build the pool key from host, port, and TLS flag.
fn pool_key(host: &str, port: u16, is_tls: bool) -> String {
    if is_tls {
        format!("{}:{}:tls", host, port)
    } else {
        format!("{}:{}", host, port)
    }
}

/// Remove stale connections from a Vec, closing their TCP sockets.
fn evict_stale_vec(conns: &mut Vec<PooledConnection>, now_ms: u64) {
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

/// Evict the single oldest connection across all hosts. Returns true if one was evicted.
fn evict_oldest_global(map: &mut BTreeMap<String, Vec<PooledConnection>>) -> bool {
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

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_conn(conn_id: u32, last_used_ms: u64, is_tls: bool) -> PooledConnection {
        PooledConnection {
            conn_id,
            tls: None,
            last_used_ms,
            request_count: 0,
            is_tls,
        }
    }

    #[test]
    fn test_pool_key_format() {
        assert_eq!(pool_key("example.com", 443, true), "example.com:443:tls");
        assert_eq!(pool_key("example.com", 80, false), "example.com:80");
        assert_eq!(pool_key("localhost", 8080, false), "localhost:8080");
    }

    #[test]
    fn test_pool_new_is_empty() {
        let pool = ConnectionPool::new();
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn test_pool_release_and_len() {
        let pool = ConnectionPool::new();
        let conn = make_conn(100, 1000, true);
        pool.release("example.com", 443, conn, true);
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn test_pool_release_no_keep_alive_drops() {
        let pool = ConnectionPool::new();
        let conn = make_conn(101, 1000, true);
        pool.release("example.com", 443, conn, false);
        // Connection: close means don't pool
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn test_pool_release_max_requests_drops() {
        let pool = ConnectionPool::new();
        let mut conn = make_conn(102, 1000, true);
        conn.request_count = MAX_REQUESTS_PER_CONN;
        pool.release("example.com", 443, conn, true);
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn test_pool_per_host_limit() {
        let pool = ConnectionPool::new();
        // Insert MAX_PER_HOST + 1 connections for same host
        for i in 0..=(MAX_PER_HOST as u32) {
            let conn = make_conn(200 + i, 1000 + i as u64, true);
            pool.release("example.com", 443, conn, true);
        }
        // Should have evicted oldest, keeping MAX_PER_HOST
        assert_eq!(pool.len(), MAX_PER_HOST);
    }

    #[test]
    fn test_pool_clear() {
        let pool = ConnectionPool::new();
        for i in 0..5 {
            let conn = make_conn(300 + i, 1000, true);
            pool.release("example.com", 443, conn, true);
        }
        assert_eq!(pool.len(), 5);
        pool.clear();
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn test_pool_evict_stale() {
        let pool = ConnectionPool::new();
        // Insert a connection with old timestamp
        let conn = make_conn(400, 0, true); // last_used_ms = 0 (epoch)
        {
            let mut map = pool.entries.lock();
            let key = pool_key("example.com", 443, true);
            map.entry(key).or_insert_with(Vec::new).push(conn);
        }
        assert_eq!(pool.len(), 1);
        pool.evict_stale();
        // Should be evicted because idle > 60s (timestamp 0 is ancient)
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn test_pool_different_hosts() {
        let pool = ConnectionPool::new();
        let conn_a = make_conn(500, 1000, true);
        let conn_b = make_conn(501, 1000, true);
        pool.release("a.com", 443, conn_a, true);
        pool.release("b.com", 443, conn_b, true);
        assert_eq!(pool.len(), 2);
    }

    #[test]
    fn test_pool_tls_vs_plain_separate() {
        let pool = ConnectionPool::new();
        let conn_tls = make_conn(600, 1000, true);
        let conn_plain = make_conn(601, 1000, false);
        pool.release("example.com", 80, conn_tls, true);
        pool.release("example.com", 80, conn_plain, true);
        // Different pool keys (tls vs non-tls)
        assert_eq!(pool.len(), 2);
    }

    #[test]
    fn test_pool_total_limit() {
        let pool = ConnectionPool::new();
        // Fill pool to MAX_TOTAL with different hosts
        for i in 0..MAX_TOTAL as u32 {
            let conn = make_conn(700 + i, 1000 + i as u64, true);
            let host = format!("host{}.com", i);
            pool.release(&host, 443, conn, true);
        }
        assert_eq!(pool.len(), MAX_TOTAL);

        // Adding one more should evict the oldest
        let extra = make_conn(999, 5000, true);
        pool.release("extra.com", 443, extra, true);
        assert_eq!(pool.len(), MAX_TOTAL);
    }

    #[test]
    fn test_evict_stale_vec_removes_old() {
        let mut conns = vec![
            make_conn(800, 0, true),          // ancient — should be evicted
            make_conn(801, u64::MAX / 2, true), // far future — should be kept
        ];
        evict_stale_vec(&mut conns, IDLE_TIMEOUT_MS + 1);
        assert_eq!(conns.len(), 1);
        assert_eq!(conns[0].conn_id, 801);
    }

    #[test]
    fn test_evict_stale_vec_keeps_fresh() {
        let now = 100_000u64;
        let mut conns = vec![
            make_conn(810, now - 1_000, true),   // 1 second ago — fresh
            make_conn(811, now - 30_000, true),  // 30 seconds ago — fresh
        ];
        evict_stale_vec(&mut conns, now);
        assert_eq!(conns.len(), 2);
    }
}
