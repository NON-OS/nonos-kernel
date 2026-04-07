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
use alloc::collections::BTreeSet;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::RwLock;

static IP_BLACKLIST: RwLock<BTreeSet<u32>> = RwLock::new(BTreeSet::new());
static IP_WHITELIST: RwLock<BTreeSet<u32>> = RwLock::new(BTreeSet::new());
static SUBNET_BLACKLIST: RwLock<BTreeSet<(u32, u8)>> = RwLock::new(BTreeSet::new());
static BLACKLIST_HITS: AtomicU64 = AtomicU64::new(0);
static WHITELIST_HITS: AtomicU64 = AtomicU64::new(0);

fn ip_to_u32(ip: [u8; 4]) -> u32 {
    ((ip[0] as u32) << 24) | ((ip[1] as u32) << 16) | ((ip[2] as u32) << 8) | (ip[3] as u32)
}

fn subnet_mask(prefix: u8) -> u32 {
    if prefix == 0 { 0 } else { !0u32 << (32 - prefix) }
}

pub fn add_to_blacklist(ip: [u8; 4]) { IP_BLACKLIST.write().insert(ip_to_u32(ip)); }
pub fn remove_from_blacklist(ip: [u8; 4]) { IP_BLACKLIST.write().remove(&ip_to_u32(ip)); }
pub fn add_to_whitelist(ip: [u8; 4]) { IP_WHITELIST.write().insert(ip_to_u32(ip)); }
pub fn remove_from_whitelist(ip: [u8; 4]) { IP_WHITELIST.write().remove(&ip_to_u32(ip)); }

pub fn add_subnet_blacklist(network: [u8; 4], prefix: u8) {
    if prefix <= 32 { SUBNET_BLACKLIST.write().insert((ip_to_u32(network), prefix)); }
}

pub fn remove_subnet_blacklist(network: [u8; 4], prefix: u8) {
    SUBNET_BLACKLIST.write().remove(&(ip_to_u32(network), prefix));
}

pub fn is_whitelisted(ip: [u8; 4]) -> bool {
    let ip_u32 = ip_to_u32(ip);
    if IP_WHITELIST.read().contains(&ip_u32) {
        WHITELIST_HITS.fetch_add(1, Ordering::Relaxed);
        return true;
    }
    false
}

pub fn is_blacklisted(ip: [u8; 4]) -> bool {
    let ip_u32 = ip_to_u32(ip);
    if IP_BLACKLIST.read().contains(&ip_u32) {
        BLACKLIST_HITS.fetch_add(1, Ordering::Relaxed);
        return true;
    }
    for &(network, prefix) in SUBNET_BLACKLIST.read().iter() {
        let mask = subnet_mask(prefix);
        if (ip_u32 & mask) == (network & mask) {
            BLACKLIST_HITS.fetch_add(1, Ordering::Relaxed);
            return true;
        }
    }
    false
}

pub fn check_ip(ip: [u8; 4]) -> bool {
    if is_whitelisted(ip) { return true; }
    !is_blacklisted(ip)
}

pub fn blacklist_count() -> usize { IP_BLACKLIST.read().len() + SUBNET_BLACKLIST.read().len() }
pub fn whitelist_count() -> usize { IP_WHITELIST.read().len() }
pub fn get_stats() -> (u64, u64) {
    (BLACKLIST_HITS.load(Ordering::Relaxed), WHITELIST_HITS.load(Ordering::Relaxed))
}
