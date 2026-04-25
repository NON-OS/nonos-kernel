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

#[derive(Clone, Copy, Debug, Default)]
pub struct SmartData {
    pub temperature: u16,
    pub power_on_hours: u32,
    pub power_cycles: u64,
    pub unsafe_shutdowns: u64,
    pub media_errors: u64,
    pub error_log_entries: u64,
    pub critical_warning: u8,
    pub available_spare: u8,
    pub available_spare_threshold: u8,
    pub percentage_used: u8,
    pub data_units_read: u64,
    pub data_units_written: u64,
    pub host_read_commands: u64,
    pub host_write_commands: u64,
    pub reallocated_sectors: u32,
    pub pending_sectors: u32,
    pub health_status: u8,
}

impl SmartData {
    pub fn temperature_celsius(&self) -> u16 {
        self.temperature
    }
    pub fn power_on_hours(&self) -> u32 {
        self.power_on_hours
    }
    pub fn power_cycles(&self) -> u64 {
        self.power_cycles
    }
    pub fn unsafe_shutdowns(&self) -> u64 {
        self.unsafe_shutdowns
    }
    pub fn media_errors(&self) -> u64 {
        self.media_errors
    }
    pub fn error_log_entries(&self) -> u64 {
        self.error_log_entries
    }
    pub fn has_critical_warning(&self) -> bool {
        self.critical_warning != 0
    }
    pub fn available_spare(&self) -> u8 {
        self.available_spare
    }
    pub fn spare_threshold(&self) -> u8 {
        self.available_spare_threshold
    }
    pub fn is_spare_low(&self) -> bool {
        self.available_spare < self.available_spare_threshold
    }
    pub fn percentage_used(&self) -> u8 {
        self.percentage_used
    }
    pub fn data_units_read(&self) -> u64 {
        self.data_units_read
    }
    pub fn data_units_written(&self) -> u64 {
        self.data_units_written
    }
    pub fn read_commands(&self) -> u64 {
        self.host_read_commands
    }
    pub fn write_commands(&self) -> u64 {
        self.host_write_commands
    }
    pub fn reallocated_sectors(&self) -> u32 {
        self.reallocated_sectors
    }
    pub fn pending_sectors(&self) -> u32 {
        self.pending_sectors
    }
    pub fn health_status(&self) -> u8 {
        self.health_status
    }
    pub fn is_healthy(&self) -> bool {
        self.health_status == 0 && !self.has_critical_warning()
    }
}
