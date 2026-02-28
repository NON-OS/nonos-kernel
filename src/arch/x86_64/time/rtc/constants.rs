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

pub const UNIX_EPOCH_YEAR: u16 = 1970;

pub const SECS_PER_MIN: u64 = 60;

pub const SECS_PER_HOUR: u64 = 3600;

pub const SECS_PER_DAY: u64 = 86400;

pub mod ports {
    pub const CMOS_ADDR: u16 = 0x70;
    pub const CMOS_DATA: u16 = 0x71;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Register {
    Seconds = 0x00,
    SecondsAlarm = 0x01,
    Minutes = 0x02,
    MinutesAlarm = 0x03,
    Hours = 0x04,
    HoursAlarm = 0x05,
    DayOfWeek = 0x06,
    DayOfMonth = 0x07,
    Month = 0x08,
    Year = 0x09,
    StatusA = 0x0A,
    StatusB = 0x0B,
    StatusC = 0x0C,
    StatusD = 0x0D,
    Century = 0x32,
    FloppyTypes = 0x10,
    HardDiskTypes = 0x12,
    Equipment = 0x14,
    BaseMemoryLow = 0x15,
    BaseMemoryHigh = 0x16,
    ExtendedMemoryLow = 0x17,
    ExtendedMemoryHigh = 0x18,
    ChecksumHigh = 0x2E,
    ChecksumLow = 0x2F,
    PostStatus = 0x0E,
    ShutdownStatus = 0x0F,
}

pub mod status_a {
    pub const UIP: u8 = 0x80;
    pub const RATE_MASK: u8 = 0x0F;
}

pub mod status_b {
    pub const HOUR_24: u8 = 0x02;
    pub const DM: u8 = 0x04;
    pub const UIE: u8 = 0x10;
    pub const AIE: u8 = 0x20;
    pub const PIE: u8 = 0x40;
    pub const SET: u8 = 0x80;
}

pub mod status_c {
    pub const UF: u8 = 0x10;
    pub const AF: u8 = 0x20;
    pub const PF: u8 = 0x40;
}

pub mod status_d {
    pub const VRT: u8 = 0x80;
}
