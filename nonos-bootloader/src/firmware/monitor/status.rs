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

use crate::firmware::types::FirmwareType;
use super::health::HealthStatus;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusFlag(u32);

#[derive(Debug, Clone)]
pub struct FirmwareStatus { firmware_type: FirmwareType, flags: StatusFlag, health: HealthStatus, uptime_seconds: u32, last_error_code: u32, restart_count: u16 }

#[derive(Debug, Clone)]
pub struct StatusMonitor { statuses: [Option<FirmwareStatus>; 64], monitor_interval: u32, last_update: u64 }

static mut GLOBAL_MONITOR: StatusMonitor = StatusMonitor::new();

impl StatusFlag {
    pub const NONE: Self = Self(0);
    pub const LOADED: Self = Self(1 << 0);
    pub const ACTIVE: Self = Self(1 << 1);
    pub const ERROR: Self = Self(1 << 2);
    pub const UPDATING: Self = Self(1 << 3);
    pub const DEGRADED: Self = Self(1 << 4);
    pub const CRITICAL: Self = Self(1 << 5);
    pub fn contains(&self, other: Self) -> bool { (self.0 & other.0) == other.0 }
    pub fn union(&self, other: Self) -> Self { Self(self.0 | other.0) }
    pub fn remove(&self, other: Self) -> Self { Self(self.0 & !other.0) }
}

pub fn get_firmware_status(firmware_type: FirmwareType) -> Option<FirmwareStatus> {
    unsafe { GLOBAL_MONITOR.get_status(firmware_type) }
}

pub fn update_status(firmware_type: FirmwareType, flags: StatusFlag, health: HealthStatus) -> bool {
    unsafe { GLOBAL_MONITOR.update_firmware_status(firmware_type, flags, health) }
}

impl StatusMonitor {
    const fn new() -> Self { Self { statuses: [None; 64], monitor_interval: 5000, last_update: 0 } }
    fn get_status(&self, firmware_type: FirmwareType) -> Option<FirmwareStatus> { self.statuses.iter().filter_map(|s| s.as_ref()).find(|s| s.firmware_type == firmware_type).cloned() }
    fn update_firmware_status(&mut self, firmware_type: FirmwareType, flags: StatusFlag, health: HealthStatus) -> bool {
        if let Some(existing) = self.find_status_mut(firmware_type) { existing.flags = flags; existing.health = health; existing.uptime_seconds += 1; return true; }
        if let Some(empty_slot) = self.find_empty_slot() { *empty_slot = Some(FirmwareStatus::new(firmware_type, flags, health)); return true; }
        false
    }
    fn find_status_mut(&mut self, firmware_type: FirmwareType) -> Option<&mut FirmwareStatus> { self.statuses.iter_mut().filter_map(|s| s.as_mut()).find(|s| s.firmware_type == firmware_type) }
    fn find_empty_slot(&mut self) -> Option<&mut Option<FirmwareStatus>> { self.statuses.iter_mut().find(|s| s.is_none()) }
}

impl FirmwareStatus {
    fn new(firmware_type: FirmwareType, flags: StatusFlag, health: HealthStatus) -> Self { Self { firmware_type, flags, health, uptime_seconds: 0, last_error_code: 0, restart_count: 0 } }
    pub fn is_active(&self) -> bool { self.flags.contains(StatusFlag::ACTIVE) }
    pub fn has_errors(&self) -> bool { self.flags.contains(StatusFlag::ERROR) }
    pub fn is_degraded(&self) -> bool { self.flags.contains(StatusFlag::DEGRADED) || self.health == HealthStatus::Degraded }
    pub fn get_uptime(&self) -> u32 { self.uptime_seconds }
    pub fn record_error(&mut self, error_code: u32) { self.last_error_code = error_code; self.flags = self.flags.union(StatusFlag::ERROR); }
    pub fn record_restart(&mut self) { self.restart_count += 1; self.uptime_seconds = 0; }
}