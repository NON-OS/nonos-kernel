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

#[derive(Debug, Clone, Default)]
pub struct RtcStatistics {
    pub initialized: bool,
    pub battery_good: bool,
    pub binary_mode: bool,
    pub hour_24_mode: bool,
    pub has_century: bool,
    pub timezone_offset: i32,
    pub reads: u64,
    pub writes: u64,
    pub alarm_interrupts: u64,
    pub periodic_interrupts: u64,
    pub update_interrupts: u64,
    pub last_timestamp: u64,
}
