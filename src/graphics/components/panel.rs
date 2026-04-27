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

use super::primitives;
use crate::graphics::design_system::{borders, colors, shadows};

#[derive(Clone, Copy, PartialEq)]
pub enum PanelVariant {
    Default,
    Elevated,
    Inset,
}

pub fn draw_panel(x: u32, y: u32, w: u32, h: u32, variant: PanelVariant) {
    draw_panel_with_radius(x, y, w, h, variant, borders::RADIUS_CARD)
}

pub fn draw_panel_with_radius(x: u32, y: u32, w: u32, h: u32, variant: PanelVariant, radius: u32) {
    let bg = match variant {
        PanelVariant::Default => colors::BG_SURFACE,
        PanelVariant::Elevated => colors::BG_ELEVATED,
        PanelVariant::Inset => colors::BG_APP,
    };
    if variant == PanelVariant::Elevated {
        primitives::shadow(x, y, w, h, radius, &shadows::SHADOW_MD);
    }
    primitives::rounded_rect(x, y, w, h, radius, bg);
}

pub fn draw_simple_card(x: u32, y: u32, w: u32, h: u32) {
    draw_panel(x, y, w, h, PanelVariant::Elevated)
}

pub fn draw_inset(x: u32, y: u32, w: u32, h: u32) {
    draw_panel(x, y, w, h, PanelVariant::Inset)
}

pub fn content_area(x: u32, y: u32, w: u32, h: u32, padding: u32) -> (u32, u32, u32, u32) {
    (x + padding, y + padding, w.saturating_sub(padding * 2), h.saturating_sub(padding * 2))
}
