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
use nonos_policy_proto::label_of;
use nonos_toolkit::widgets::{Ink, Rect, Row as ListRow, Scrolled, Separator, State as Look};

use crate::settings::schema::rows::{Row, Tone};
use crate::settings::state::State;

use super::bytes::as_str;
use super::control;
use super::control_geom::{right_edge, slider_x};
use super::field_note::note_of;
use super::live_value::{note, resolve};

/// Draws a card's row at `at`, in content coordinates, through the toolkit
/// row; a field's control then goes in the room the row leaves for it.
/// `selected` is the keyboard cursor.
pub fn paint(
    fb: &mut PaintBuffer,
    state: &State,
    row: &Row,
    scroll: u32,
    at: Rect,
    selected: bool,
) {
    let look = Look { focused: selected, hovered: selected, ..Look::default() };
    match row {
        Row::Field(f) => {
            let room = right_edge(at.x, at.w) - slider_x(at.x, at.w);
            let line = ListRow::new(as_str(label_of(*f))).trailing(room).state(look);
            let line = note_of(*f).map_or(line, |n| line.note(n));
            line.draw(&mut Scrolled::new(fb, scroll), at);
            control::paint(fb, state, *f, at.x, at.w, at.y as i32 - scroll as i32, at.h);
        }
        Row::Live(label, live) => {
            let (value, tone) = resolve(state, *live);
            let line = ListRow::new(label).value(value.as_str()).value_ink(ink(tone)).state(look);
            let line = note(state, *live).map_or(line, |n| line.note(n));
            line.draw(&mut Scrolled::new(fb, scroll), at);
        }
        Row::Networks | Row::Saved | Row::Wallpapers => {}
    }
}

/// The toolkit ink a live value's tone reads in.
fn ink(tone: Tone) -> Ink {
    match tone {
        Tone::Ok => Ink::Ok,
        Tone::Warn => Ink::Warn,
        Tone::Idle => Ink::Muted,
    }
}

/// The line under a row, at the row's content `y`.
pub(super) fn hairline(
    fb: &mut PaintBuffer,
    scroll: u32,
    card_x: u32,
    card_w: u32,
    y: u32,
    row_h: u32,
) {
    let at = Rect { x: card_x + 1, y: y + row_h - 1, w: card_w.saturating_sub(2), h: 1 };
    Separator::new().draw(&mut Scrolled::new(fb, scroll), at);
}
