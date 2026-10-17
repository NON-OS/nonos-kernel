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
use nonos_toolkit::design::size::CARD_HEAD_H;
use nonos_toolkit::widgets::{Card, Rect, Scrolled};

use super::metrics::CARD_PAD;
use super::mono::valid;

// A titled card's first content row, and the height its frame costs on top of
// whatever it holds. Every screen sizes its cards from these two, so a change to
// the padding moves the layout and the scroll extent together.
pub const CONTENT_TOP: u32 = CARD_HEAD_H;
pub const OVERHEAD: u32 = CONTENT_TOP + CARD_PAD;

/// The shared card with no head, `h` tall from `y`. Returns the first
/// content row, `CARD_PAD` inside its top.
pub fn panel(fb: &mut PaintBuffer, x: u32, y: i32, w: u32, h: u32) -> i32 {
    place(fb, Card::new(), x, y, w, h);
    y + CARD_PAD as i32
}

// The drawable width inside a card, which every screen needs and none should
// re-derive: the padding belongs to the card, not to the rows it holds.
pub fn inner(w: u32) -> u32 {
    w.saturating_sub(CARD_PAD * 2)
}

/// The shared card with `title` in its head. Returns the first content row,
/// under the head.
pub fn titled(fb: &mut PaintBuffer, x: u32, y: i32, w: u32, h: u32, title: &[u8]) -> i32 {
    place(fb, Card::new().title(valid(title)), x, y, w, h);
    y + CONTENT_TOP as i32
}

/// A card's top may have scrolled above the pane, and a `Rect` cannot start
/// there, so such a card is drawn through `Scrolled`, which lifts it and cuts
/// it at the pane's top.
fn place(fb: &mut PaintBuffer, card: Card, x: u32, y: i32, w: u32, h: u32) {
    match u32::try_from(y) {
        Ok(y) => card.draw(fb, Rect { x, y, w, h }),
        Err(_) => card.draw(&mut Scrolled::new(fb, y.unsigned_abs()), Rect { x, y: 0, w, h }),
    }
}
