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

//! xHCI Runtime Register offsets, relative to BAR0 + RTSOFF. The
//! per-interrupter register set starts at offset 0x20 and repeats
//! every 32 bytes (`INTERRUPTER_STRIDE`); the offsets below are
//! within one interrupter slice.

pub const INTERRUPTER_STRIDE: u64 = 0x20;

pub const IMAN: u64 = 0x00; // Interrupter Management
pub const IMOD: u64 = 0x04; // Interrupter Moderation
pub const ERSTSZ: u64 = 0x08; // Event Ring Segment Table Size
pub const ERSTBA_LO: u64 = 0x10; // 64-bit Event Ring Segment Table Base Address
pub const ERDP_LO: u64 = 0x18; // 64-bit Event Ring Dequeue Pointer
