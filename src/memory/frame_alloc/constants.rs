// NØNOS Operating System
// Copyright (C) 2024 NØNOS Contributors
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

pub const FRAME_SIZE: u64 = 4096;
pub const FRAME_SIZE_USIZE: usize = 4096;
pub const DEFAULT_REGION_START: u64 = 16 * 1024 * 1024;
pub const DEFAULT_REGION_END: u64 = 512 * 1024 * 1024;
pub const FRAME_ALIGNMENT: u64 = FRAME_SIZE;
pub const MIN_ALLOC_ADDRESS: u64 = 0x100000; // 1 MiB (above conventional memory)
pub const MAX_MEMORY_REGIONS: usize = 64;
