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

use super::constants::*;
use crate::graphics::framebuffer::fill_rect;

pub(super) fn draw_soft_shadow(x: u32, y: u32, w: u32, h: u32, focused: bool) {
    let intensity = if focused { 60u32 } else { 30 };
    for layer in 0..SHADOW_BLUR {
        let spread = layer + 1;
        let offset_y = layer / 2 + 2;
        let alpha = intensity.saturating_sub(layer * 4);
        if alpha == 0 {
            continue;
        }
        let color = alpha << 24;
        let sx = x.saturating_sub(spread / 2);
        let sy = y + offset_y;
        let sw = w + spread;
        let sh = h + spread / 2;
        fill_rect(sx + CORNER_RADIUS, sy, sw.saturating_sub(CORNER_RADIUS * 2), sh, color);
        fill_rect(sx, sy + CORNER_RADIUS, sw, sh.saturating_sub(CORNER_RADIUS * 2), color);
    }
}
