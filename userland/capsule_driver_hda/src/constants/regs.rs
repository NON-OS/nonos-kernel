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

pub const GCAP: u32 = 0x00;
pub const VMIN: u32 = 0x02;
pub const VMAJ: u32 = 0x03;
pub const OUTPAY: u32 = 0x04;
pub const INPAY: u32 = 0x06;
pub const GCTL: u32 = 0x08;
pub const STATESTS: u32 = 0x0e;
pub const GSTS: u32 = 0x10;
pub const INTCTL: u32 = 0x20;
pub const INTSTS: u32 = 0x24;

pub const GCTL_CRST: u32 = 1 << 0;
