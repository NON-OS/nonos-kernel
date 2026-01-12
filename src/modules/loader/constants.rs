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

pub const LOADER_VERSION: u16 = 1;
pub const MODULE_NAME_OFFSET: usize = 0;
pub const MODULE_NAME_SIZE: usize = 64;
pub const MODULE_SIGNATURE_OFFSET: usize = 64;
pub const MODULE_SIGNATURE_SIZE: usize = 64;
pub const MODULE_PUBKEY_OFFSET: usize = 128;
pub const MODULE_PUBKEY_SIZE: usize = 32;
pub const MODULE_HEADER_SIZE: usize = MODULE_NAME_SIZE + MODULE_SIGNATURE_SIZE + MODULE_PUBKEY_SIZE;
pub const MAX_MODULE_SIZE: usize = 16 * 1024 * 1024;
