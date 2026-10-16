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

use nonos_app_skeleton::PaintBuffer;
use nonos_toolkit::widgets::{Card, Rect, Scrolled};

use crate::settings::schema::rows::Block;
use crate::settings::state::State;

use super::card_pill::block_pill;
use super::metrics::{CARD_HEAD_H, CARD_PAD_X, PILL_H};
use super::pill;

/// Draws block `b`'s card, head included, at `at` in content coordinates.
pub fn paint(fb: &mut PaintBuffer, b: &Block, scroll: u32, at: Rect) {
    let card = Card::new().title(b.title);
    let card = b.note.map_or(card, |note| card.note(note));
    card.draw(&mut Scrolled::new(fb, scroll), at);
}

pub fn paint_pill(fb: &mut PaintBuffer, state: &State, b: &Block, x: u32, screen_y: i32, w: u32) {
    let Some((label, tone)) = block_pill(state, b) else { return };
    let pill_y = screen_y + ((CARD_HEAD_H - PILL_H) / 2) as i32;
    if pill_y >= 0 {
        pill::draw(fb, x + w - CARD_PAD_X, pill_y as u32, label.as_str(), tone);
    }
}
