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

pub const GCAP_ID: u64 = 0x000;
pub const GCONF: u64 = 0x010;
pub const GINTR_STS: u64 = 0x020;
pub const MAIN_CNT: u64 = 0x0F0;

pub const fn timer_config(n: u8) -> u64 {
    0x100 + (n as u64) * 0x20
}

pub const fn timer_comparator(n: u8) -> u64 {
    0x108 + (n as u64) * 0x20
}

pub const fn timer_fsb_route(n: u8) -> u64 {
    0x110 + (n as u64) * 0x20
}
