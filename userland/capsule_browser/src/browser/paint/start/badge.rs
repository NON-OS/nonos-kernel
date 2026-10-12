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

use nonos_app_skeleton::{measure_ttf, PaintBuffer};
use nonos_toolkit::font::ttf::line_height;

use crate::browser::paint::glyph::{self, Glyph};
use crate::browser::paint::tokens::palette;
use crate::browser::ui::rect::Rect;

const ICON: i32 = 20;
const BADGE_PX: f32 = 17.0;
const BADGE_H: i32 = 30;
const BADGE_INSET: i32 = 20;
const BADGE_PAD: i32 = 14;
const SHIELD: i32 = 16;
const BADGE: &str = "History clears at shutdown";

/// The session badge in the hero's top right corner. It stays clear of the
/// greeting ending at `greet_right`: when they would meet, it is left out.
pub fn paint(fb: &mut PaintBuffer, hero: Rect, greet_right: i32) {
    let w = measure_ttf(BADGE, BADGE_PX) + 2 * BADGE_PAD + ICON;
    let x = hero.right() - BADGE_INSET - w;
    let (y, r) = (hero.y + BADGE_INSET, BADGE_H / 2);
    if x < greet_right + BADGE_INSET || y < 0 {
        return;
    }
    fb.fill_round(x as u32, y as u32, w as u32, BADGE_H as u32, r as u32, palette().surface);
    glyph::draw(fb, Glyph::Shield, x + BADGE_PAD + SHIELD / 2, y + r, SHIELD, palette().teal);
    let ty = y + (BADGE_H - line_height(BADGE_PX)) / 2;
    fb.text_ttf(x + BADGE_PAD + ICON, ty, BADGE, palette().teal, BADGE_PX);
}
