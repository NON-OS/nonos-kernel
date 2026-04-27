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
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use spin::Mutex;

const SYN_THRESHOLD: u32 = 100;
const SYN_WINDOW_MS: u64 = 1000;
const BLOCK_DURATION_MS: u64 = 60000;

struct SynState {
    count: AtomicU32,
    window_start: AtomicU64,
}
static SYN_TRACKER: Mutex<BTreeMap<u32, SynState>> = Mutex::new(BTreeMap::new());
static BLOCKED_IPS: Mutex<BTreeMap<u32, u64>> = Mutex::new(BTreeMap::new());
static SYN_COOKIES_ENABLED: AtomicU32 = AtomicU32::new(1);

fn ip_to_u32(ip: [u8; 4]) -> u32 {
    ((ip[0] as u32) << 24) | ((ip[1] as u32) << 16) | ((ip[2] as u32) << 8) | (ip[3] as u32)
}

pub fn check_syn_flood(src_ip: [u8; 4]) -> bool {
    let ip_key = ip_to_u32(src_ip);
    let now = crate::time::timestamp_millis();
    let blocked = BLOCKED_IPS.lock();
    if let Some(&block_until) = blocked.get(&ip_key) {
        if now < block_until {
            return false;
        }
    }
    drop(blocked);
    let mut tracker = SYN_TRACKER.lock();
    let state = tracker.entry(ip_key).or_insert_with(|| SynState {
        count: AtomicU32::new(0),
        window_start: AtomicU64::new(now),
    });
    let window_start = state.window_start.load(Ordering::Relaxed);
    if now.saturating_sub(window_start) > SYN_WINDOW_MS {
        state.count.store(1, Ordering::Relaxed);
        state.window_start.store(now, Ordering::Relaxed);
        return true;
    }
    let count = state.count.fetch_add(1, Ordering::Relaxed);
    if count >= SYN_THRESHOLD {
        drop(tracker);
        BLOCKED_IPS.lock().insert(ip_key, now + BLOCK_DURATION_MS);
        crate::security::monitoring::audit::log_security_event(
            "firewall",
            crate::security::monitoring::audit::AuditSeverity::Critical,
            alloc::format!(
                "SYN flood detected from {}.{}.{}.{}",
                src_ip[0],
                src_ip[1],
                src_ip[2],
                src_ip[3]
            ),
            None,
            None,
            None,
        );
        return false;
    }
    true
}

pub fn generate_syn_cookie(src_ip: [u8; 4], src_port: u16, dst_port: u16, seq: u32) -> u32 {
    if SYN_COOKIES_ENABLED.load(Ordering::Relaxed) == 0 {
        return seq.wrapping_add(1);
    }
    let t = (crate::time::timestamp_millis() / 60000) as u32;
    let hash_input = ip_to_u32(src_ip) ^ ((src_port as u32) << 16) ^ (dst_port as u32) ^ t;
    let cookie = crate::crypto::fnv1a_u32(hash_input);
    (cookie & 0x00FFFFFF) | ((t & 0xFF) << 24)
}

pub fn verify_syn_cookie(src_ip: [u8; 4], src_port: u16, dst_port: u16, ack: u32) -> bool {
    if SYN_COOKIES_ENABLED.load(Ordering::Relaxed) == 0 {
        return true;
    }
    let t_recv = ((ack >> 24) & 0xFF) as u32;
    let t_now = (crate::time::timestamp_millis() / 60000) as u32;
    if t_now.wrapping_sub(t_recv) > 2 {
        return false;
    }
    let hash_input = ip_to_u32(src_ip) ^ ((src_port as u32) << 16) ^ (dst_port as u32) ^ t_recv;
    let expected = crate::crypto::fnv1a_u32(hash_input);
    (ack & 0x00FFFFFF) == (expected & 0x00FFFFFF)
}

pub fn is_blocked(ip: [u8; 4]) -> bool {
    let now = crate::time::timestamp_millis();
    BLOCKED_IPS.lock().get(&ip_to_u32(ip)).map(|&t| now < t).unwrap_or(false)
}

pub fn unblock_ip(ip: [u8; 4]) {
    BLOCKED_IPS.lock().remove(&ip_to_u32(ip));
}
pub fn enable_syn_cookies(enable: bool) {
    SYN_COOKIES_ENABLED.store(enable as u32, Ordering::Relaxed);
}
