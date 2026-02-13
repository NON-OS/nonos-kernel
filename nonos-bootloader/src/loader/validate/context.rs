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

pub struct ValidationContext {
    pub is_64bit: bool,
    pub is_little_endian: bool,
    pub is_executable: bool,
    pub is_pie: bool,
    pub machine: u16,
    pub entry_point: u64,
    pub min_addr: u64,
    pub max_addr: u64,
    pub total_size: usize,
    pub segment_count: usize,
    pub has_dynamic: bool,
    pub wx_segments: usize,
}

impl Default for ValidationContext {
    fn default() -> Self {
        Self {
            is_64bit: false,
            is_little_endian: false,
            is_executable: false,
            is_pie: false,
            machine: 0,
            entry_point: 0,
            min_addr: u64::MAX,
            max_addr: 0,
            total_size: 0,
            segment_count: 0,
            has_dynamic: false,
            wx_segments: 0,
        }
    }
}
