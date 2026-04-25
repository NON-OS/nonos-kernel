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

#![allow(static_mut_refs)]

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityEvent { FirmwareLoaded, ValidationFailed, ThreatDetected, SandboxViolation, UnauthorizedAccess, IntegrityBreach }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditResult { Logged, BufferFull, InvalidEvent, SystemError }

static mut AUDIT_BUFFER: [AuditEntry; 256] = [AuditEntry::empty(); 256];
static mut AUDIT_INDEX: usize = 0;

#[derive(Debug, Clone, Copy)]
struct AuditEntry { timestamp: u64, event: SecurityEvent, severity: u8, context: u32 }

impl AuditEntry {
    const fn empty() -> Self { Self { timestamp: 0, event: SecurityEvent::FirmwareLoaded, severity: 0, context: 0 } }
    pub fn get_event(&self) -> SecurityEvent { self.event }
    pub fn get_severity(&self) -> u8 { self.severity }
    pub fn get_context(&self) -> u32 { self.context }
    pub fn get_timestamp(&self) -> u64 { self.timestamp }
}

pub fn log_firmware_access(firmware_id: u32, access_type: u8) -> AuditResult {
    let event = match access_type { 0 => SecurityEvent::FirmwareLoaded, 1 => SecurityEvent::ValidationFailed, _ => SecurityEvent::UnauthorizedAccess };
    log_security_event(event, calculate_severity(event), firmware_id)
}

pub fn log_security_event(event: SecurityEvent, severity: u8, context: u32) -> AuditResult {
    unsafe {
        if AUDIT_INDEX >= AUDIT_BUFFER.len() { return AuditResult::BufferFull; }
        let timestamp = get_system_timestamp();
        let entry = AuditEntry { timestamp, event, severity, context };
        AUDIT_BUFFER[AUDIT_INDEX] = entry;
        AUDIT_INDEX += 1;
        if should_alert(event, severity) { trigger_security_alert(event, context); }
        AuditResult::Logged
    }
}

fn calculate_severity(event: SecurityEvent) -> u8 {
    match event { SecurityEvent::FirmwareLoaded => 1, SecurityEvent::ValidationFailed => 3, SecurityEvent::UnauthorizedAccess => 4, SecurityEvent::ThreatDetected => 5, SecurityEvent::SandboxViolation => 4, SecurityEvent::IntegrityBreach => 5 }
}

pub fn get_high_severity_count() -> usize {
    unsafe { AUDIT_BUFFER[..AUDIT_INDEX].iter().filter(|e| e.get_severity() >= 4).count() }
}

pub fn get_latest_event() -> Option<(SecurityEvent, u64, u32)> {
    unsafe { if AUDIT_INDEX == 0 { None } else { let e = &AUDIT_BUFFER[AUDIT_INDEX - 1]; Some((e.get_event(), e.get_timestamp(), e.get_context())) } }
}

fn get_system_timestamp() -> u64 { static mut COUNTER: u64 = 0; unsafe { COUNTER += 1; COUNTER } }
fn should_alert(event: SecurityEvent, severity: u8) -> bool { severity >= 4 || matches!(event, SecurityEvent::ThreatDetected | SecurityEvent::IntegrityBreach) }
fn trigger_security_alert(_event: SecurityEvent, _context: u32) { }