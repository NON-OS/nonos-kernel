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

pub mod audit;
pub mod leak_detection;
pub mod monitor;
pub mod rootkit;

pub use audit::{
    audit_event, clear_audit_log, get_audit_log, init as audit_init, log_security_event,
    log_security_violation, AuditEvent, AuditSeverity, SecurityAuditEvent,
};

pub use monitor::{
    get_recent_events, get_stats as monitor_stats, is_enabled, log_event, set_enabled,
    MonitorStats, SecurityEvent, SecurityEventType,
};

pub use rootkit::{
    get_last_scan as rootkit_last_scan, init as rootkit_init, scan_system as rootkit_scan,
    RootkitScanResult,
};

pub use leak_detection::{
    add_sensitive_pattern, get_last_scan as leak_last_scan, list_sensitive_patterns,
    scan_filesystem as leak_scan_filesystem, scan_memory as leak_scan_memory,
    scan_network as leak_scan_network, LeakFinding, LeakLocation, LeakScanResult,
};
