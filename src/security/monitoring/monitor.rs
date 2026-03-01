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

use alloc::{string::String, vec::Vec};
use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use spin::{Mutex, Once};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityEventType {
    SuspiciousMemoryAccess,
    UnauthorizedNetworkAccess,
    ProcessAnomaly,
    HardwareTamper,
    PrivilegeEscalation,
    SyscallAnomaly,
    FilesystemViolation,
    CapabilityAbuse,
    PrivacyViolation,
    RootkitDetection,
    IntegrityBreach,
}

#[derive(Debug, Clone)]
pub struct SecurityEvent {
    pub timestamp: u64,
    pub event_type: SecurityEventType,
    pub severity: u8,
    pub description: String,
    pub process_id: Option<u64>,
    pub module: Option<String>,
    pub extra_tags: Option<Vec<String>>,
}

#[derive(Default, Debug)]
pub struct MonitorStats {
    pub total_events: AtomicU64,
    pub critical_events: AtomicU64,
    pub memory_violations: AtomicU64,
    pub network_anomalies: AtomicU64,
    pub process_anomalies: AtomicU64,
    pub rootkit_alerts: AtomicU64,
    pub privacy_violations: AtomicU64,
}

static MONITOR_LOG: Mutex<Vec<SecurityEvent>> = Mutex::new(Vec::new());
static MONITOR_STATS: Once<MonitorStats> = Once::new();

fn get_monitor_stats() -> &'static MonitorStats {
    MONITOR_STATS.call_once(|| MonitorStats::default())
}
static MONITOR_ENABLED: AtomicBool = AtomicBool::new(true);

pub fn log_event(
    event_type: SecurityEventType,
    severity: u8,
    description: String,
    process_id: Option<u64>,
    module: Option<String>,
    extra_tags: Option<Vec<String>>,
) {
    let event = SecurityEvent {
        timestamp: crate::time::timestamp_millis(),
        event_type,
        severity,
        description,
        process_id,
        module,
        extra_tags,
    };
    {
        let mut log = MONITOR_LOG.lock();
        if log.len() > 4096 {
            log.remove(0);
        }
        log.push(event.clone());
    }
    get_monitor_stats().total_events.fetch_add(1, Ordering::Relaxed);
    if severity >= 3 {
        get_monitor_stats().critical_events.fetch_add(1, Ordering::Relaxed);
    }
    let _ = match event_type {
        SecurityEventType::SuspiciousMemoryAccess => get_monitor_stats().memory_violations.fetch_add(1, Ordering::Relaxed),
        SecurityEventType::UnauthorizedNetworkAccess => get_monitor_stats().network_anomalies.fetch_add(1, Ordering::Relaxed),
        SecurityEventType::ProcessAnomaly => get_monitor_stats().process_anomalies.fetch_add(1, Ordering::Relaxed),
        SecurityEventType::RootkitDetection => get_monitor_stats().rootkit_alerts.fetch_add(1, Ordering::Relaxed),
        SecurityEventType::PrivacyViolation => get_monitor_stats().privacy_violations.fetch_add(1, Ordering::Relaxed),
        _ => 0,
    };
}

pub fn get_recent_events(n: usize) -> Vec<SecurityEvent> {
    let log = MONITOR_LOG.lock();
    let len = log.len();
    log.iter().skip(len.saturating_sub(n)).cloned().collect()
}

pub fn get_stats() -> MonitorStats {
    MonitorStats {
        total_events: AtomicU64::new(get_monitor_stats().total_events.load(Ordering::Relaxed)),
        critical_events: AtomicU64::new(get_monitor_stats().critical_events.load(Ordering::Relaxed)),
        memory_violations: AtomicU64::new(get_monitor_stats().memory_violations.load(Ordering::Relaxed)),
        network_anomalies: AtomicU64::new(get_monitor_stats().network_anomalies.load(Ordering::Relaxed)),
        process_anomalies: AtomicU64::new(get_monitor_stats().process_anomalies.load(Ordering::Relaxed)),
        rootkit_alerts: AtomicU64::new(get_monitor_stats().rootkit_alerts.load(Ordering::Relaxed)),
        privacy_violations: AtomicU64::new(get_monitor_stats().privacy_violations.load(Ordering::Relaxed)),
    }
}

pub fn set_enabled(enabled: bool) {
    MONITOR_ENABLED.store(enabled, Ordering::Relaxed);
}

pub fn is_enabled() -> bool {
    MONITOR_ENABLED.load(Ordering::Relaxed)
}
