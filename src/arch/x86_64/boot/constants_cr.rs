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

pub const CR0_PE: u64 = 1 << 0;
pub const CR0_MP: u64 = 1 << 1;
pub const CR0_EM: u64 = 1 << 2;
pub const CR0_TS: u64 = 1 << 3;
pub const CR0_ET: u64 = 1 << 4;
pub const CR0_NE: u64 = 1 << 5;
pub const CR0_WP: u64 = 1 << 16;
pub const CR0_AM: u64 = 1 << 18;
pub const CR0_NW: u64 = 1 << 29;
pub const CR0_CD: u64 = 1 << 30;
pub const CR0_PG: u64 = 1 << 31;

pub const CR4_VME: u64 = 1 << 0;
pub const CR4_PVI: u64 = 1 << 1;
pub const CR4_TSD: u64 = 1 << 2;
pub const CR4_DE: u64 = 1 << 3;
pub const CR4_PSE: u64 = 1 << 4;
pub const CR4_PAE: u64 = 1 << 5;
pub const CR4_MCE: u64 = 1 << 6;
pub const CR4_PGE: u64 = 1 << 7;
pub const CR4_PCE: u64 = 1 << 8;
pub const CR4_OSFXSR: u64 = 1 << 9;
pub const CR4_OSXMMEXCPT: u64 = 1 << 10;
pub const CR4_UMIP: u64 = 1 << 11;
pub const CR4_FSGSBASE: u64 = 1 << 16;
pub const CR4_PCIDE: u64 = 1 << 17;
pub const CR4_OSXSAVE: u64 = 1 << 18;
pub const CR4_SMEP: u64 = 1 << 20;
pub const CR4_SMAP: u64 = 1 << 21;
