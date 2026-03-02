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


pub const INITIAL_MODULE_ID: u64 = 1;

pub const MODULE_HASH_SIZE: usize = 32;

pub const MODULE_SIGNATURE_SIZE: usize = 64;

pub const MIN_ENTRY_POINT_SIZE: usize = 8;

pub const DEFAULT_NOP_SLED_SIZE: usize = 4096;

pub const NOP_INSTRUCTION: u8 = 0x90;
