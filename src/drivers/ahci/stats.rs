// NØNOS Operating System
// Copyright (C) 2025 NØNOS Contributors
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
//
//! Provides runtime statistics for monitoring and debugging.
#[derive(Debug, Default, Clone, Copy)]
pub struct AhciStats {
    /// Total read operations completed
    pub read_ops: u64,
    /// Total write operations completed
    pub write_ops: u64,
    /// Total TRIM operations completed
    pub trim_ops: u64,
    /// Total errors encountered
    pub errors: u64,
    /// Total bytes read
    pub bytes_read: u64,
    /// Total bytes written
    pub bytes_written: u64,
    /// Number of detected devices
    pub devices_count: u32,
    /// Number of port resets performed
    pub port_resets: u64,
    /// Number of validation failures
    pub validation_failures: u64,
}
