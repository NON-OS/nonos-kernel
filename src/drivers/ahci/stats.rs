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

//! AHCI controller statistics.

#[derive(Debug, Default, Clone, Copy)]
pub struct AhciStats {
    pub read_ops: u64,
    pub write_ops: u64,
    pub trim_ops: u64,
    pub errors: u64,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub devices_count: u32,
    pub port_resets: u64,
    pub validation_failures: u64,
}
