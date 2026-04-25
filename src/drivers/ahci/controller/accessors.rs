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

use super::super::stats::AhciStats;
use super::structure::AhciController;
use alloc::{string::String, vec::Vec};
use core::sync::atomic::Ordering;

impl AhciController {
    pub fn set_command_timeout(&self, timeout: u32) {
        self.command_timeout.store(timeout, Ordering::Relaxed);
    }
    pub fn is_encryption_enabled(&self) -> bool {
        self.encryption_enabled.load(Ordering::Relaxed)
    }
    pub fn set_encryption_enabled(&self, enabled: bool) {
        self.encryption_enabled.store(enabled, Ordering::Relaxed);
    }
    pub fn get_device_ports(&self) -> Vec<u32> {
        self.ports.read().keys().copied().collect()
    }

    pub fn get_device_info(&self, port: u32) -> Option<(String, u64, bool)> {
        self.ports.read().get(&port).map(|d| (d.model.clone(), d.sectors, d.supports_trim))
    }

    pub fn get_stats(&self) -> AhciStats {
        AhciStats {
            read_ops: self.read_ops.load(Ordering::Relaxed),
            write_ops: self.write_ops.load(Ordering::Relaxed),
            trim_ops: self.trim_ops.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            bytes_read: self.bytes_read.load(Ordering::Relaxed),
            bytes_written: self.bytes_written.load(Ordering::Relaxed),
            devices_count: self.ports.read().len() as u32,
            port_resets: self.port_resets.load(Ordering::Relaxed),
            validation_failures: self.validation_failures.load(Ordering::Relaxed),
        }
    }
}
