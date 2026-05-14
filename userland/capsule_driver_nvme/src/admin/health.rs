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

#[derive(Clone, Copy)]
pub struct SmartHealth {
    pub critical_warning: u8,
    pub temperature_kelvin: u16,
    pub available_spare: u8,
    pub available_spare_threshold: u8,
    pub percentage_used: u8,
    pub endurance_group_warning: u8,
    pub data_units_read: u128,
    pub data_units_written: u128,
    pub host_read_commands: u128,
    pub host_write_commands: u128,
    pub controller_busy_time: u128,
    pub power_cycles: u128,
    pub power_on_hours: u128,
    pub unsafe_shutdowns: u128,
    pub media_errors: u128,
    pub error_log_entries: u128,
    pub warning_temp_time: u32,
    pub critical_temp_time: u32,
}

impl SmartHealth {
    pub fn parse(data: &[u8]) -> Self {
        Self {
            critical_warning: data[0],
            temperature_kelvin: le16(data, 1),
            available_spare: data[3],
            available_spare_threshold: data[4],
            percentage_used: data[5],
            endurance_group_warning: data[6],
            data_units_read: le128(data, 32),
            data_units_written: le128(data, 48),
            host_read_commands: le128(data, 64),
            host_write_commands: le128(data, 80),
            controller_busy_time: le128(data, 96),
            power_cycles: le128(data, 112),
            power_on_hours: le128(data, 128),
            unsafe_shutdowns: le128(data, 144),
            media_errors: le128(data, 160),
            error_log_entries: le128(data, 176),
            warning_temp_time: le32(data, 192),
            critical_temp_time: le32(data, 196),
        }
    }

    pub fn temperature_celsius(&self) -> i16 {
        (self.temperature_kelvin as i32 - 273) as i16
    }
}

fn le16(data: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([data[off], data[off + 1]])
}

fn le32(data: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
}

fn le128(data: &[u8], off: usize) -> u128 {
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&data[off..off + 16]);
    u128::from_le_bytes(bytes)
}
