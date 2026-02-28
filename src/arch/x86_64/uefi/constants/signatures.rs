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

pub const RUNTIME_SERVICES_SIGNATURE: u64 = 0x56524553544E5552;

pub const BOOT_SERVICES_SIGNATURE: u64 = 0x56524553544F4F42;

pub const SYSTEM_TABLE_SIGNATURE: u64 = 0x5453595320494249;

pub const MAX_VARIABLE_NAME_LENGTH: usize = 256;

pub const MAX_VARIABLE_DATA_SIZE: usize = 1024 * 1024;

pub const SIGNATURE_LIST_HEADER_SIZE: usize = 28;

pub const SIGNATURE_DATA_HEADER_SIZE: usize = 16;

pub const SHA256_HASH_SIZE: usize = 32;

pub const SHA384_HASH_SIZE: usize = 48;

pub const SHA512_HASH_SIZE: usize = 64;
