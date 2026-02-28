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

use super::constants::Register;
use super::cmos::{cmos_read, cmos_write};

pub fn calculate_checksum() -> u16 {
    let mut sum: u16 = 0;
    for addr in 0x10..=0x2D {
        sum = sum.wrapping_add(cmos_read(addr) as u16);
    }
    sum
}

pub fn read_checksum() -> u16 {
    let high = cmos_read(Register::ChecksumHigh as u8) as u16;
    let low = cmos_read(Register::ChecksumLow as u8) as u16;
    (high << 8) | low
}

pub fn write_checksum(checksum: u16) {
    cmos_write(Register::ChecksumHigh as u8, (checksum >> 8) as u8);
    cmos_write(Register::ChecksumLow as u8, (checksum & 0xFF) as u8);
}

pub fn verify_checksum() -> bool {
    calculate_checksum() == read_checksum()
}

pub fn update_checksum() {
    let checksum = calculate_checksum();
    write_checksum(checksum);
}
