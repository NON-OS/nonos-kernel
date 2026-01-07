// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use core::sync::atomic::{AtomicU64, Ordering};
#[derive(Default)]
pub struct XhciStatistics {
    pub interrupts: AtomicU64,
    pub commands_completed: AtomicU64,
    pub transfers_completed: AtomicU64,
    pub bytes_transferred: AtomicU64,
    pub devices_enumerated: AtomicU64,
    pub port_status_changes: AtomicU64,
    pub timeouts: AtomicU64,
    pub invalid_slot_errors: AtomicU64,
    pub invalid_port_errors: AtomicU64,
    pub trb_validation_errors: AtomicU64,
    pub dma_validation_errors: AtomicU64,
    pub descriptor_validation_errors: AtomicU64,
    pub command_errors: AtomicU64,
    pub transfer_errors: AtomicU64,
    pub stall_errors: AtomicU64,
    pub babble_errors: AtomicU64,
    pub short_packets: AtomicU64,
    pub enumeration_rate_limit_hits: AtomicU64,
    pub security_events: AtomicU64,
    pub control_transfers: AtomicU64,
    pub bulk_transfers: AtomicU64,
    pub interrupt_transfers: AtomicU64,
    pub isoch_transfers: AtomicU64,
}

impl XhciStatistics {
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    pub fn inc_interrupts(&self) {
        self.interrupts.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_commands(&self) {
        self.commands_completed.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_transfers(&self) {
        self.transfers_completed.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn add_bytes(&self, bytes: u64) {
        self.bytes_transferred.fetch_add(bytes, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_timeouts(&self) {
        self.timeouts.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_stalls(&self) {
        self.stall_errors.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_security_events(&self) {
        self.security_events.fetch_add(1, Ordering::Relaxed);
    }

    pub fn total_errors(&self) -> u64 {
        self.timeouts.load(Ordering::Relaxed)
            + self.invalid_slot_errors.load(Ordering::Relaxed)
            + self.invalid_port_errors.load(Ordering::Relaxed)
            + self.trb_validation_errors.load(Ordering::Relaxed)
            + self.dma_validation_errors.load(Ordering::Relaxed)
            + self.descriptor_validation_errors.load(Ordering::Relaxed)
            + self.command_errors.load(Ordering::Relaxed)
            + self.transfer_errors.load(Ordering::Relaxed)
            + self.stall_errors.load(Ordering::Relaxed)
            + self.babble_errors.load(Ordering::Relaxed)
    }

    pub fn snapshot(&self) -> XhciStats {
        let devices = self.devices_enumerated.load(Ordering::Relaxed);
        XhciStats {
            transfers: self.transfers_completed.load(Ordering::Relaxed),
            errors: self.total_errors(),
            interrupts: self.interrupts.load(Ordering::Relaxed),
            bytes_transferred: self.bytes_transferred.load(Ordering::Relaxed),
            devices_connected: if devices > 0 { devices } else { 0 },
            max_slots: 0,
            max_ports: 0,
            commands_completed: self.commands_completed.load(Ordering::Relaxed),
            devices_enumerated: devices,
            timeouts: self.timeouts.load(Ordering::Relaxed),
            stall_errors: self.stall_errors.load(Ordering::Relaxed),
            security_events: self.security_events.load(Ordering::Relaxed),
        }
    }

    pub fn snapshot_with_info(&self, max_slots: u8, max_ports: u8, devices: u64) -> XhciStats {
        let mut stats = self.snapshot();
        stats.max_slots = max_slots as u64;
        stats.max_ports = max_ports as u64;
        stats.devices_connected = devices;
        stats
    }

    pub fn reset(&self) {
        self.interrupts.store(0, Ordering::Relaxed);
        self.commands_completed.store(0, Ordering::Relaxed);
        self.transfers_completed.store(0, Ordering::Relaxed);
        self.bytes_transferred.store(0, Ordering::Relaxed);
        self.devices_enumerated.store(0, Ordering::Relaxed);
        self.port_status_changes.store(0, Ordering::Relaxed);
        self.timeouts.store(0, Ordering::Relaxed);
        self.invalid_slot_errors.store(0, Ordering::Relaxed);
        self.invalid_port_errors.store(0, Ordering::Relaxed);
        self.trb_validation_errors.store(0, Ordering::Relaxed);
        self.dma_validation_errors.store(0, Ordering::Relaxed);
        self.descriptor_validation_errors.store(0, Ordering::Relaxed);
        self.command_errors.store(0, Ordering::Relaxed);
        self.transfer_errors.store(0, Ordering::Relaxed);
        self.stall_errors.store(0, Ordering::Relaxed);
        self.babble_errors.store(0, Ordering::Relaxed);
        self.short_packets.store(0, Ordering::Relaxed);
        self.enumeration_rate_limit_hits.store(0, Ordering::Relaxed);
        self.security_events.store(0, Ordering::Relaxed);
        self.control_transfers.store(0, Ordering::Relaxed);
        self.bulk_transfers.store(0, Ordering::Relaxed);
        self.interrupt_transfers.store(0, Ordering::Relaxed);
        self.isoch_transfers.store(0, Ordering::Relaxed);
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct XhciStats {
    pub transfers: u64,
    pub errors: u64,
    pub interrupts: u64,
    pub bytes_transferred: u64,
    pub devices_connected: u64,
    pub max_slots: u64,
    pub max_ports: u64,
    pub commands_completed: u64,
    pub devices_enumerated: u64,
    pub timeouts: u64,
    pub stall_errors: u64,
    pub security_events: u64,
}

impl XhciStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn error_rate(&self) -> f64 {
        let total = self.transfers + self.errors;
        if total == 0 {
            0.0
        } else {
            (self.errors as f64 / total as f64) * 100.0
        }
    }

    pub fn avg_bytes_per_transfer(&self) -> u64 {
        if self.transfers == 0 {
            0
        } else {
            self.bytes_transferred / self.transfers
        }
    }

    pub fn total_errors(&self) -> u64 {
        self.errors
    }

    pub fn transfers_completed(&self) -> u64 {
        self.transfers
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControllerHealth {
    Healthy,
    Warning,
    Critical,
    NotInitialized,
}

impl ControllerHealth {
    pub fn from_stats(stats: &XhciStats) -> Self {
        if stats.transfers == 0 && stats.commands_completed == 0 {
            return ControllerHealth::NotInitialized;
        }

        let error_rate = stats.error_rate();
        if error_rate > 10.0 {
            ControllerHealth::Critical
        } else if error_rate > 1.0 || stats.security_events > 0 {
            ControllerHealth::Warning
        } else {
            ControllerHealth::Healthy
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ControllerHealth::Healthy => "Healthy",
            ControllerHealth::Warning => "Warning",
            ControllerHealth::Critical => "Critical",
            ControllerHealth::NotInitialized => "Not Initialized",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stats_increment() {
        let stats = XhciStatistics::new();
        stats.inc_interrupts();
        stats.inc_commands();
        stats.inc_transfers();
        stats.add_bytes(1024);

        assert_eq!(stats.interrupts.load(Ordering::Relaxed), 1);
        assert_eq!(stats.commands_completed.load(Ordering::Relaxed), 1);
        assert_eq!(stats.transfers_completed.load(Ordering::Relaxed), 1);
        assert_eq!(stats.bytes_transferred.load(Ordering::Relaxed), 1024);
    }

    #[test]
    fn test_stats_snapshot() {
        let stats = XhciStatistics::new();
        stats.inc_transfers();
        stats.inc_transfers();
        stats.add_bytes(2048);

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.transfers, 2);
        assert_eq!(snapshot.bytes_transferred, 2048);
    }

    #[test]
    fn test_error_rate() {
        let mut stats = XhciStats::new();
        stats.transfers = 90;
        stats.errors = 10;

        assert!((stats.error_rate() - 10.0).abs() < 0.01);
    }

    #[test]
    fn test_controller_health() {
        let mut stats = XhciStats::new();
        stats.transfers = 100;
        stats.errors = 0;

        assert_eq!(
            ControllerHealth::from_stats(&stats),
            ControllerHealth::Healthy
        );

        stats.errors = 5;
        assert_eq!(
            ControllerHealth::from_stats(&stats),
            ControllerHealth::Warning
        );

        stats.errors = 20;
        assert_eq!(
            ControllerHealth::from_stats(&stats),
            ControllerHealth::Critical
        );
    }
}
