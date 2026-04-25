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

use super::orders::{MAX_ORDER, MIN_ORDER};

pub const MIN_BLOCK_SIZE: usize = 1 << MIN_ORDER;
pub const MAX_BLOCK_SIZE: usize = 1 << MAX_ORDER;
pub const PAGE_SIZE: usize = 4096;
pub const PAGE_SIZE_U64: u64 = PAGE_SIZE as u64;
pub const MIN_ALIGNMENT: usize = PAGE_SIZE;
pub const MAX_ALIGNMENT: usize = MAX_BLOCK_SIZE;
