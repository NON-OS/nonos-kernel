// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use super::scale::SPACE_UNIT;

#[inline]
pub const fn space(multiplier: u32) -> u32 {
    SPACE_UNIT * multiplier
}

#[inline]
pub const fn center(container_size: u32, item_size: u32) -> u32 {
    if container_size > item_size {
        (container_size - item_size) / 2
    } else {
        0
    }
}

#[inline]
pub const fn center_text_y(container_height: u32) -> u32 {
    center(container_height, 16)
}

#[inline]
pub const fn clamp(value: u32, min: u32, max: u32) -> u32 {
    if value < min {
        min
    } else if value > max {
        max
    } else {
        value
    }
}
