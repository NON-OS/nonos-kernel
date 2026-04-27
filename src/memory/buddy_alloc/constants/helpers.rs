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
use super::sizes::MIN_BLOCK_SIZE;

#[inline]
pub const fn order_to_size(order: usize) -> usize {
    1 << order
}

#[inline]
pub const fn size_to_order(size: usize) -> usize {
    let size = if size < MIN_BLOCK_SIZE { MIN_BLOCK_SIZE } else { size };
    let mut order = MIN_ORDER;
    while (1 << order) < size && order < MAX_ORDER {
        order += 1;
    }
    order
}

#[inline]
pub const fn buddy_address(addr: u64, order: usize) -> u64 {
    addr ^ (1u64 << order)
}
