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

pub mod bridge_offsets {
    pub const PRIMARY_BUS: u16 = 0x18;
    pub const SECONDARY_BUS: u16 = 0x19;
    pub const SUBORDINATE_BUS: u16 = 0x1A;
    pub const SECONDARY_LATENCY: u16 = 0x1B;
    pub const IO_BASE: u16 = 0x1C;
    pub const IO_LIMIT: u16 = 0x1D;
    pub const SECONDARY_STATUS: u16 = 0x1E;
    pub const MEMORY_BASE: u16 = 0x20;
    pub const MEMORY_LIMIT: u16 = 0x22;
    pub const PREFETCH_BASE: u16 = 0x24;
    pub const PREFETCH_LIMIT: u16 = 0x26;
    pub const PREFETCH_BASE_UPPER: u16 = 0x28;
    pub const PREFETCH_LIMIT_UPPER: u16 = 0x2C;
    pub const IO_BASE_UPPER: u16 = 0x30;
    pub const IO_LIMIT_UPPER: u16 = 0x32;
    pub const BRIDGE_CONTROL: u16 = 0x3E;
}

pub mod command_bits {
    pub const IO_SPACE: u16 = 1 << 0;
    pub const MEMORY_SPACE: u16 = 1 << 1;
    pub const BUS_MASTER: u16 = 1 << 2;
    pub const SPECIAL_CYCLES: u16 = 1 << 3;
    pub const MWI_ENABLE: u16 = 1 << 4;
    pub const VGA_PALETTE_SNOOP: u16 = 1 << 5;
    pub const PARITY_ERROR_RESPONSE: u16 = 1 << 6;
    pub const SERR_ENABLE: u16 = 1 << 8;
    pub const FAST_B2B_ENABLE: u16 = 1 << 9;
    pub const INT_DISABLE: u16 = 1 << 10;
}

pub mod status_bits {
    pub const INT_STATUS: u16 = 1 << 3;
    pub const CAP_LIST: u16 = 1 << 4;
    pub const MHZ_66_CAPABLE: u16 = 1 << 5;
    pub const FAST_B2B_CAPABLE: u16 = 1 << 7;
    pub const MASTER_PARITY_ERROR: u16 = 1 << 8;
    pub const DEVSEL_MASK: u16 = 0x03 << 9;
    pub const SIG_TARGET_ABORT: u16 = 1 << 11;
    pub const RCV_TARGET_ABORT: u16 = 1 << 12;
    pub const RCV_MASTER_ABORT: u16 = 1 << 13;
    pub const SIG_SYSTEM_ERROR: u16 = 1 << 14;
    pub const DETECTED_PARITY_ERROR: u16 = 1 << 15;
}
