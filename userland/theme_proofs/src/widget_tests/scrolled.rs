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

//! Scrolled: a widget drawn through it at content coordinates lands only in
//! its box moved up by the scroll and cut to the buffer.

use nonos_toolkit::icons::IconId;
use nonos_toolkit::paint::PaintBuffer;
use nonos_toolkit::widgets::{Card, Field, Rect, Row, Scrolled, Switch};

use super::boxes::inside;
use super::canvas::Canvas;
use super::serial::serial;

/// Draws a card, a row, a field with an icon and a switch at content
/// coordinates in `at`.
fn content(fb: &mut Scrolled<'_, '_>, at: Rect) {
    Card::new().title("Network").note("Grüße — 日本語").draw(fb, at);
    Row::new("Wi-Fi").value("Home").chevron().draw(fb, at);
    Field::new("Grüße").icon(IconId::SettingsSearch).draw(fb, at);
    Switch::new(true).draw(fb, at);
}

#[test]
fn scrolled_draws_only_in_the_box_moved_up_and_cut() {
    let _g = serial();
    let screen = Rect { x: 0, y: 0, w: 320, h: 120 };
    for scroll in [0u32, 10, 30, 60, 100, 200] {
        for top in [20u32, 50, 90, 140] {
            let at = Rect { x: 30, y: top, w: 240, h: 60 };
            let paint = |fb: &mut PaintBuffer<'_>| content(&mut Scrolled::new(fb, scroll), at);
            let c = Canvas::new(Rect { h: 96, ..screen }, 0).painted(paint);
            let (y0, y1) = (top.saturating_sub(scroll), (top + at.h).saturating_sub(scroll));
            let shown = Rect { y: y0, h: y1 - y0, ..at };
            let stray = c.changed(0).into_iter().find(|&p| !inside(shown, p));
            assert!(stray.is_none(), "scroll {scroll}, top {top}: {stray:?} outside {shown:?}");
        }
    }
}
