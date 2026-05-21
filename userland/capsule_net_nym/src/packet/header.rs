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

pub const WIRE_MAGIC: u32 = 0x4E59_4D50;
pub const WIRE_VERSION: u8 = 1;
pub const OFF_FLAGS: usize = 5;
pub const OFF_SESSION: usize = 8;
pub const OFF_NONCE: usize = 12;
pub const OFF_REPLAY_TAG: usize = 24;
pub const OFF_HEADER_RANDOM: usize = 56;
