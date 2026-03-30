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

pub const REGION_FLAG_READONLY: u32 = 0x0001;
pub const REGION_FLAG_UNCACHED: u32 = 0x0002;
pub const REGION_FLAG_WRITE_THROUGH: u32 = 0x0004;
pub const REGION_FLAG_WRITE_COMBINE: u32 = 0x0008;
pub const REGION_FLAG_FIRMWARE: u32 = 0x0010;
pub const REGION_FLAG_RECLAIMABLE: u32 = 0x0020;
