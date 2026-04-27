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

pub const RADIUS_NONE: u32 = 0;
pub const RADIUS_XS: u32 = 2;
pub const RADIUS_SM: u32 = 4;
pub const RADIUS_MD: u32 = 8;
pub const RADIUS_LG: u32 = 12;
pub const RADIUS_XL: u32 = 16;
pub const RADIUS_2XL: u32 = 24;
pub const RADIUS_FULL: u32 = 9999;

pub const RADIUS_WINDOW: u32 = RADIUS_LG;
pub const RADIUS_BUTTON: u32 = RADIUS_MD;
pub const RADIUS_INPUT: u32 = RADIUS_MD;
pub const RADIUS_CARD: u32 = RADIUS_LG;
pub const RADIUS_DIALOG: u32 = RADIUS_XL;
pub const RADIUS_TOOLTIP: u32 = RADIUS_SM;
pub const RADIUS_BADGE: u32 = RADIUS_SM;
pub const RADIUS_DOCK: u32 = RADIUS_XL;
pub const RADIUS_MENU: u32 = RADIUS_MD;
pub const RADIUS_SCROLLBAR: u32 = RADIUS_SM;

pub const BORDER_NONE: u32 = 0;
pub const BORDER_THIN: u32 = 1;
pub const BORDER_NORMAL: u32 = 2;
pub const BORDER_THICK: u32 = 3;
pub const BORDER_FOCUS_WIDTH: u32 = 2;

#[inline]
pub const fn clamp_radius(radius: u32, width: u32, height: u32) -> u32 {
    let max = if width < height { width / 2 } else { height / 2 };
    if radius > max {
        max
    } else {
        radius
    }
}

#[inline]
pub const fn is_pill(radius: u32, width: u32, height: u32) -> bool {
    let min = if width < height { width } else { height };
    radius >= min / 2
}
