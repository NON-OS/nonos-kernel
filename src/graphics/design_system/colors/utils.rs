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

#[inline]
pub fn blend_alpha(bg: u32, fg: u32, alpha: u8) -> u32 {
    let a = alpha as u32;
    let inv_a = 255 - a;
    let r = ((((fg >> 16) & 0xFF) * a + ((bg >> 16) & 0xFF) * inv_a) / 255) & 0xFF;
    let g = ((((fg >> 8) & 0xFF) * a + ((bg >> 8) & 0xFF) * inv_a) / 255) & 0xFF;
    let b = (((fg & 0xFF) * a + (bg & 0xFF) * inv_a) / 255) & 0xFF;
    0xFF000000 | (r << 16) | (g << 8) | b
}

#[inline]
pub fn lighten(color: u32, percent: u32) -> u32 {
    let factor = 100 + percent;
    let r = core::cmp::min((((color >> 16) & 0xFF) * factor) / 100, 255);
    let g = core::cmp::min((((color >> 8) & 0xFF) * factor) / 100, 255);
    let b = core::cmp::min(((color & 0xFF) * factor) / 100, 255);
    0xFF000000 | (r << 16) | (g << 8) | b
}

#[inline]
pub fn darken(color: u32, percent: u32) -> u32 {
    let factor = 100 - percent.min(100);
    let r = (((color >> 16) & 0xFF) * factor) / 100;
    let g = (((color >> 8) & 0xFF) * factor) / 100;
    let b = ((color & 0xFF) * factor) / 100;
    0xFF000000 | (r << 16) | (g << 8) | b
}

#[inline]
pub const fn with_alpha(color: u32, alpha: u8) -> u32 {
    (color & 0x00FFFFFF) | ((alpha as u32) << 24)
}
