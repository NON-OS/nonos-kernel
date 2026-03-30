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

pub const PERM_READ: u32 = 1 << 0;
pub const PERM_WRITE: u32 = 1 << 1;
pub const PERM_EXECUTE: u32 = 1 << 2;
pub const PERM_USER: u32 = 1 << 3;
pub const PERM_GLOBAL: u32 = 1 << 4;
pub const PERM_NO_CACHE: u32 = 1 << 5;
pub const PERM_WRITE_THROUGH: u32 = 1 << 6;
pub const PERM_COW: u32 = 1 << 7;
pub const PERM_DEMAND: u32 = 1 << 8;
pub const PERM_ZERO_FILL: u32 = 1 << 9;
pub const PERM_SHARED: u32 = 1 << 10;
pub const PERM_LOCKED: u32 = 1 << 11;
pub const PERM_DEVICE: u32 = 1 << 12;
