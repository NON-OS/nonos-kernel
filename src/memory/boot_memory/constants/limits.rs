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

use super::page_sizes::PAGE_SIZE_U64;

pub const MAX_BOOT_REGIONS: usize = 256;
pub const MIN_REGION_SIZE: u64 = PAGE_SIZE_U64;
pub const MAX_ALLOCATION_SIZE: usize = 256 * 1024 * 1024;
pub const BOOT_ENTROPY_SIZE: usize = 32;
