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
use super::address::Ipv6Address;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use spin::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeighborState {
    Incomplete,
    Reachable,
    Stale,
    Delay,
    Probe,
}

#[derive(Debug, Clone)]
pub struct NeighborEntry {
    pub ip: Ipv6Address,
    pub mac: [u8; 6],
    pub state: NeighborState,
    pub updated: u64,
    pub probes: u8,
    pub is_router: bool,
}

pub struct NeighborCache {
    entries: BTreeMap<[u8; 16], NeighborEntry>,
    pending: Vec<(Ipv6Address, u64)>,
}

const REACHABLE_TIME_MS: u64 = 30000;
const STALE_TIME_MS: u64 = 60000;
const DELAY_FIRST_PROBE_MS: u64 = 5000;
const MAX_PROBES: u8 = 3;

static NEIGHBOR_CACHE: Mutex<NeighborCache> =
    Mutex::new(NeighborCache { entries: BTreeMap::new(), pending: Vec::new() });

impl NeighborCache {
    pub fn lookup(&self, ip: &Ipv6Address) -> Option<&NeighborEntry> {
        self.entries.get(&ip.0)
    }

    pub fn insert(&mut self, entry: NeighborEntry) {
        self.pending.retain(|(addr, _)| addr != &entry.ip);
        self.entries.insert(entry.ip.0, entry);
    }

    pub fn update(&mut self, ip: &Ipv6Address, mac: [u8; 6], is_router: bool) {
        let now = crate::sys::clock::uptime_ms();
        if let Some(entry) = self.entries.get_mut(&ip.0) {
            entry.mac = mac;
            entry.state = NeighborState::Reachable;
            entry.updated = now;
            entry.is_router = is_router;
            entry.probes = 0;
        } else {
            self.insert(NeighborEntry {
                ip: *ip,
                mac,
                state: NeighborState::Reachable,
                updated: now,
                probes: 0,
                is_router,
            });
        }
    }

    pub fn mark_stale(&mut self, ip: &Ipv6Address) {
        if let Some(entry) = self.entries.get_mut(&ip.0) {
            entry.state = NeighborState::Stale;
            entry.updated = crate::sys::clock::uptime_ms();
        }
    }

    pub fn start_probe(&mut self, ip: &Ipv6Address) {
        let now = crate::sys::clock::uptime_ms();
        if !self.pending.iter().any(|(a, _)| a == ip) {
            self.pending.push((*ip, now));
        }
        self.entries.entry(ip.0).or_insert(NeighborEntry {
            ip: *ip,
            mac: [0; 6],
            state: NeighborState::Incomplete,
            updated: now,
            probes: 1,
            is_router: false,
        });
    }

    pub fn expire(&mut self) {
        let now = crate::sys::clock::uptime_ms();
        self.entries.retain(|_, e| match e.state {
            NeighborState::Reachable => now - e.updated < REACHABLE_TIME_MS,
            NeighborState::Stale => now - e.updated < STALE_TIME_MS,
            NeighborState::Incomplete => e.probes < MAX_PROBES,
            _ => true,
        });
        self.pending.retain(|(_, t)| now - *t < DELAY_FIRST_PROBE_MS);
    }
}

pub fn resolve_neighbor(ip: &Ipv6Address) -> Option<[u8; 6]> {
    let cache = NEIGHBOR_CACHE.lock();
    cache
        .lookup(ip)
        .filter(|e| e.state == NeighborState::Reachable || e.state == NeighborState::Stale)
        .map(|e| e.mac)
}

pub fn update_neighbor(ip: &Ipv6Address, mac: [u8; 6], is_router: bool) {
    NEIGHBOR_CACHE.lock().update(ip, mac, is_router);
}

pub fn start_neighbor_discovery(ip: &Ipv6Address) {
    NEIGHBOR_CACHE.lock().start_probe(ip);
}
pub fn expire_neighbors() {
    NEIGHBOR_CACHE.lock().expire();
}
