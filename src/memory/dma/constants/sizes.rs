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

use crate::memory::layout;

pub const DEFAULT_ALIGNMENT: usize = layout::PAGE_SIZE;
pub const DEFAULT_MAX_SEGMENT_SIZE: usize = 1024 * 1024;
pub const DMA32_LIMIT: u64 = 1u64 << 32;
pub const MIN_DMA_SIZE: usize = 1;
pub const MAX_DMA_SIZE: usize = 256 * 1024 * 1024;
