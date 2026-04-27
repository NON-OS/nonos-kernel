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

#[derive(Clone, Copy)]
pub struct Shadow {
    pub layers: u32,
    pub offset_x: i32,
    pub offset_y: i32,
    pub spread: u32,
    pub base_alpha: u32,
    pub alpha_decay: u32,
    pub color: u32,
}

impl Shadow {
    pub const fn new(layers: u32, offset_y: i32, spread: u32, base_alpha: u32, decay: u32) -> Self {
        Self { layers, offset_x: 0, offset_y, spread, base_alpha, alpha_decay: decay, color: 0 }
    }
}

pub const SHADOW_NONE: Shadow = Shadow::new(0, 0, 0, 0, 0);
pub const SHADOW_XS: Shadow = Shadow::new(2, 1, 0, 10, 4);
pub const SHADOW_SM: Shadow = Shadow::new(3, 2, 1, 15, 4);
pub const SHADOW_MD: Shadow = Shadow::new(5, 4, 2, 25, 4);
pub const SHADOW_LG: Shadow = Shadow::new(8, 8, 4, 35, 4);
pub const SHADOW_XL: Shadow = Shadow::new(12, 12, 6, 40, 3);

pub const SHADOW_WINDOW: Shadow = Shadow::new(6, 4, 2, 40, 5);
pub const SHADOW_WINDOW_UNFOCUSED: Shadow = Shadow::new(4, 2, 1, 20, 4);
pub const SHADOW_DIALOG: Shadow = Shadow::new(10, 10, 5, 50, 4);
pub const SHADOW_DOCK: Shadow = Shadow::new(4, -2, 2, 30, 6);
pub const SHADOW_TOOLTIP: Shadow = Shadow::new(3, 2, 1, 20, 5);
pub const SHADOW_DROPDOWN: Shadow = Shadow::new(6, 4, 2, 35, 5);

pub const SHADOW_FOCUS: Shadow = Shadow {
    layers: 4,
    offset_x: 0,
    offset_y: 0,
    spread: 3,
    base_alpha: 60,
    alpha_decay: 12,
    color: 0x66FFFF,
};
pub const SHADOW_FOCUS_ERROR: Shadow = Shadow {
    layers: 4,
    offset_x: 0,
    offset_y: 0,
    spread: 3,
    base_alpha: 60,
    alpha_decay: 12,
    color: 0xFF5252,
};
pub const SHADOW_FOCUS_SUCCESS: Shadow = Shadow {
    layers: 4,
    offset_x: 0,
    offset_y: 0,
    spread: 3,
    base_alpha: 60,
    alpha_decay: 12,
    color: 0x00E676,
};

#[inline]
pub fn shadow_color_for_layer(shadow: &Shadow, layer: u32) -> u32 {
    let alpha = shadow.base_alpha.saturating_sub(layer * shadow.alpha_decay);
    if alpha == 0 {
        0
    } else {
        ((alpha & 0xFF) << 24) | shadow.color
    }
}

#[inline]
pub const fn is_visible(shadow: &Shadow) -> bool {
    shadow.layers > 0 && shadow.base_alpha > 0
}
