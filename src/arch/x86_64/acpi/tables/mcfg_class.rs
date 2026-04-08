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

pub mod class_codes {
    pub const UNCLASSIFIED: u8 = 0x00;
    pub const MASS_STORAGE: u8 = 0x01;
    pub const NETWORK: u8 = 0x02;
    pub const DISPLAY: u8 = 0x03;
    pub const MULTIMEDIA: u8 = 0x04;
    pub const MEMORY: u8 = 0x05;
    pub const BRIDGE: u8 = 0x06;
    pub const SIMPLE_COMM: u8 = 0x07;
    pub const BASE_SYSTEM: u8 = 0x08;
    pub const INPUT: u8 = 0x09;
    pub const DOCKING_STATION: u8 = 0x0A;
    pub const PROCESSOR: u8 = 0x0B;
    pub const SERIAL_BUS: u8 = 0x0C;
    pub const WIRELESS: u8 = 0x0D;
    pub const INTELLIGENT_IO: u8 = 0x0E;
    pub const SATELLITE_COMM: u8 = 0x0F;
    pub const ENCRYPTION: u8 = 0x10;
    pub const SIGNAL_PROCESSING: u8 = 0x11;
    pub const PROCESSING_ACCELERATOR: u8 = 0x12;
    pub const NON_ESSENTIAL: u8 = 0x13;
    pub const CO_PROCESSOR: u8 = 0x40;
    pub const UNASSIGNED: u8 = 0xFF;
}

pub mod bar_bits {
    pub const IO_SPACE: u32 = 1 << 0;
    pub const TYPE_MASK: u32 = 0x06;
    pub const TYPE_32BIT: u32 = 0x00;
    pub const TYPE_64BIT: u32 = 0x04;
    pub const PREFETCHABLE: u32 = 1 << 3;
    pub const MEMORY_MASK: u32 = !0x0F;
    pub const IO_MASK: u32 = !0x03;
}
