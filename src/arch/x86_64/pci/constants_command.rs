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

pub const IO_SPACE: u16 = 1 << 0;
pub const MEMORY_SPACE: u16 = 1 << 1;
pub const BUS_MASTER: u16 = 1 << 2;
pub const SPECIAL_CYCLES: u16 = 1 << 3;
pub const MWI_ENABLE: u16 = 1 << 4;
pub const VGA_PALETTE_SNOOP: u16 = 1 << 5;
pub const PARITY_ERROR_RESPONSE: u16 = 1 << 6;
pub const SERR_ENABLE: u16 = 1 << 8;
pub const FAST_B2B_ENABLE: u16 = 1 << 9;
pub const INTERRUPT_DISABLE: u16 = 1 << 10;
