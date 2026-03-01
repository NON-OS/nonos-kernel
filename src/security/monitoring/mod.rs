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
pub mod monitor;
pub mod rootkit;
pub mod leak_detection;

pub use audit::{
    init as audit_init, AuditSeverity, SecurityAuditEvent, log_security_event,
    log_security_violation, get_audit_log, clear_audit_log, AuditEvent, audit_event,
};

pub use monitor::{
    SecurityEventType, SecurityEvent, MonitorStats, log_event, get_recent_events,
    get_stats as monitor_stats, set_enabled, is_enabled,
};

pub use rootkit::{
    init as rootkit_init, RootkitScanResult, scan_system as rootkit_scan,
    get_last_scan as rootkit_last_scan,
};

pub use leak_detection::{
    LeakScanResult, LeakFinding, LeakLocation, add_sensitive_pattern,
    list_sensitive_patterns, scan_memory as leak_scan_memory, scan_filesystem as leak_scan_filesystem,
    scan_network as leak_scan_network, get_last_scan as leak_last_scan,
};
