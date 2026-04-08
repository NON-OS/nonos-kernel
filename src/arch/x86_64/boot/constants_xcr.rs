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

pub const XCR0_X87: u64 = 1 << 0;
pub const XCR0_SSE: u64 = 1 << 1;
pub const XCR0_AVX: u64 = 1 << 2;
pub const XCR0_BNDREG: u64 = 1 << 3;
pub const XCR0_BNDCSR: u64 = 1 << 4;
pub const XCR0_OPMASK: u64 = 1 << 5;
pub const XCR0_ZMM_HI256: u64 = 1 << 6;
pub const XCR0_HI16_ZMM: u64 = 1 << 7;
