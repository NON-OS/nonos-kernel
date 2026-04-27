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

use super::{primitives, text};
use crate::graphics::design_system::{borders, colors, shadows, spacing};

#[derive(Clone, Copy, PartialEq)]
pub enum ButtonVariant {
    Primary,
    Secondary,
    Danger,
    Ghost,
}

#[derive(Clone, Copy, PartialEq)]
pub enum ButtonSize {
    Small,
    Medium,
    Large,
}

#[derive(Clone, Copy, Default)]
pub struct ButtonState {
    pub hovered: bool,
    pub pressed: bool,
    pub disabled: bool,
}

pub fn button_height(size: ButtonSize) -> u32 {
    match size {
        ButtonSize::Small => spacing::BUTTON_HEIGHT_SM,
        ButtonSize::Medium => spacing::BUTTON_HEIGHT_MD,
        ButtonSize::Large => spacing::BUTTON_HEIGHT_LG,
    }
}

pub fn button_width(label_len: usize, size: ButtonSize) -> u32 {
    let padding = match size {
        ButtonSize::Small => spacing::BUTTON_PADDING_SM,
        ButtonSize::Medium => spacing::BUTTON_PADDING_MD,
        ButtonSize::Large => spacing::BUTTON_PADDING_LG,
    };
    (label_len as u32 * 8) + padding * 2
}

pub fn draw_button(
    x: u32,
    y: u32,
    label: &[u8],
    variant: ButtonVariant,
    size: ButtonSize,
    state: ButtonState,
) {
    let h = button_height(size);
    let w = button_width(label.len(), size);
    let radius = borders::RADIUS_BUTTON;

    let (bg, text_color) = match (variant, state.disabled, state.pressed, state.hovered) {
        (_, true, _, _) => (colors::BG_DISABLED, colors::TEXT_DISABLED),
        (ButtonVariant::Primary, _, true, _) => (colors::ACCENT, colors::TEXT_INVERSE),
        (ButtonVariant::Primary, _, _, true) => {
            (colors::BUTTON_PRIMARY_HOVER, colors::TEXT_INVERSE)
        }
        (ButtonVariant::Primary, _, _, _) => {
            (colors::BUTTON_PRIMARY_BG, colors::BUTTON_PRIMARY_TEXT)
        }
        (ButtonVariant::Secondary, _, true, _) => (colors::BG_ACTIVE, colors::TEXT_PRIMARY),
        (ButtonVariant::Secondary, _, _, true) => {
            (colors::BUTTON_SECONDARY_HOVER, colors::TEXT_PRIMARY)
        }
        (ButtonVariant::Secondary, _, _, _) => {
            (colors::BUTTON_SECONDARY_BG, colors::BUTTON_SECONDARY_TEXT)
        }
        (ButtonVariant::Danger, _, _, _) => (colors::BUTTON_DANGER_BG, colors::BUTTON_DANGER_TEXT),
        (ButtonVariant::Ghost, _, _, true) => (colors::BUTTON_GHOST_HOVER, colors::TEXT_PRIMARY),
        (ButtonVariant::Ghost, _, _, _) => (0, colors::TEXT_PRIMARY),
    };

    if variant != ButtonVariant::Ghost {
        primitives::shadow(x, y, w, h, radius, &shadows::SHADOW_SM);
    }
    if bg != 0 {
        primitives::rounded_rect(x, y, w, h, radius, bg);
    }
    let text_y = y + (h - 16) / 2;
    text::draw_centered(x, text_y, w, label, text_color);
}

pub fn button_hit_test(
    x: u32,
    y: u32,
    label_len: usize,
    size: ButtonSize,
    click_x: i32,
    click_y: i32,
) -> bool {
    let w = button_width(label_len, size);
    let h = button_height(size);
    click_x >= x as i32
        && click_x < (x + w) as i32
        && click_y >= y as i32
        && click_y < (y + h) as i32
}
