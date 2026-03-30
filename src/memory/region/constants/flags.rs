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

pub const FLAG_READABLE: u32 = 1 << 0;
pub const FLAG_WRITABLE: u32 = 1 << 1;
pub const FLAG_EXECUTABLE: u32 = 1 << 2;
pub const FLAG_CACHEABLE: u32 = 1 << 3;
pub const FLAG_SHARED: u32 = 1 << 4;
pub const FLAG_LOCKED: u32 = 1 << 5;
pub const FLAG_PROTECTED: u32 = 1 << 6;
pub const FLAG_ENCRYPTED: u32 = 1 << 7;
