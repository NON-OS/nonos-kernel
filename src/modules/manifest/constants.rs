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

pub const MANIFEST_VERSION: u16 = 1;
pub const MAX_MODULE_NAME_LEN: usize = 64;
pub const MAX_VERSION_LEN: usize = 32;
pub const MAX_AUTHOR_LEN: usize = 128;
pub const MAX_DESCRIPTION_LEN: usize = 512;
pub const MAX_CAPABILITIES: usize = 64;
pub const HASH_SIZE: usize = 32;
pub const DEFAULT_MIN_HEAP: usize = 4096;
pub const DEFAULT_MAX_HEAP: usize = 1024 * 1024;
pub const DEFAULT_STACK_SIZE: usize = 8192;
