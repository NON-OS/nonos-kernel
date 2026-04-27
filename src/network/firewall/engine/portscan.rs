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
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

const SCAN_THRESHOLD: usize = 15;
const SCAN_WINDOW_MS: u64 = 5000;
const BLOCK_DURATION_MS: u64 = 300000;

struct ScanState {
    ports: [u16; 32],
    count: usize,
    window_start: u64,
}
static SCAN_TRACKER: Mutex<BTreeMap<u32, ScanState>> = Mutex::new(BTreeMap::new());
static BLOCKED_SCANNERS: Mutex<BTreeMap<u32, u64>> = Mutex::new(BTreeMap::new());
static DETECTED_SCANS: AtomicU64 = AtomicU64::new(0);

fn ip_to_u32(ip: [u8; 4]) -> u32 {
    ((ip[0] as u32) << 24) | ((ip[1] as u32) << 16) | ((ip[2] as u32) << 8) | (ip[3] as u32)
}

pub fn track_connection_attempt(src_ip: [u8; 4], dst_port: u16) -> bool {
    let ip_key = ip_to_u32(src_ip);
    let now = crate::time::timestamp_millis();
    if let Some(&block_until) = BLOCKED_SCANNERS.lock().get(&ip_key) {
        if now < block_until {
            return false;
        }
    }
    let mut tracker = SCAN_TRACKER.lock();
    let state = tracker.entry(ip_key).or_insert_with(|| ScanState {
        ports: [0; 32],
        count: 0,
        window_start: now,
    });
    if now.saturating_sub(state.window_start) > SCAN_WINDOW_MS {
        state.ports = [0; 32];
        state.count = 0;
        state.window_start = now;
    }
    let mut already_seen = false;
    for i in 0..state.count {
        if state.ports[i] == dst_port {
            already_seen = true;
            break;
        }
    }
    if !already_seen && state.count < 32 {
        state.ports[state.count] = dst_port;
        state.count += 1;
    }
    if state.count >= SCAN_THRESHOLD {
        drop(tracker);
        BLOCKED_SCANNERS.lock().insert(ip_key, now + BLOCK_DURATION_MS);
        DETECTED_SCANS.fetch_add(1, Ordering::Relaxed);
        crate::security::monitoring::audit::log_security_event(
            "firewall",
            crate::security::monitoring::audit::AuditSeverity::Warning,
            alloc::format!(
                "Port scan detected from {}.{}.{}.{}",
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

pub fn is_scanner_blocked(ip: [u8; 4]) -> bool {
    let now = crate::time::timestamp_millis();
    BLOCKED_SCANNERS.lock().get(&ip_to_u32(ip)).map(|&t| now < t).unwrap_or(false)
}

pub fn unblock_scanner(ip: [u8; 4]) {
    BLOCKED_SCANNERS.lock().remove(&ip_to_u32(ip));
}
pub fn get_detected_scans() -> u64 {
    DETECTED_SCANS.load(Ordering::Relaxed)
}
pub fn cleanup_expired() {
    let now = crate::time::timestamp_millis();
    BLOCKED_SCANNERS.lock().retain(|_, &mut t| now < t);
    SCAN_TRACKER.lock().retain(|_, s| now.saturating_sub(s.window_start) <= SCAN_WINDOW_MS * 2);
}
