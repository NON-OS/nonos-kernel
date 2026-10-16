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

//! Card: every head stays in the box, the hit test takes the body, the
//! content area lies clear of the head text, and both inks read.

use nonos_toolkit::widgets::{Card, Rect};

use super::agree::assert_agree;
use super::bounds::assert_bounded_in;
use super::boxes::{boxed, within, FREE_W};
use super::canvas::Canvas;
use super::samples::LONG;
use super::serial::serial;

fn variants() -> Vec<(String, Card<'static>)> {
    let named = |n: &str, c| (n.to_string(), c);
    vec![
        named("bare", Card::new()),
        named("title", Card::new().title("Network")),
        named("title and note", Card::new().title("Network").note("Wi-Fi and Ethernet")),
        named("note alone", Card::new().note("no head")),
        named("long", Card::new().title(LONG).note(LONG)),
    ]
}

fn place((_, h): (u32, u32)) -> [Rect; 4] {
    [boxed(FREE_W, h), boxed(FREE_W, h + 96), boxed(FREE_W + 160, h + 136), boxed(90, h + 96)]
}

#[test]
fn card_paints_inside_its_box() {
    let _g = serial();
    assert_bounded_in(&variants(), place);
}

#[test]
fn card_hit_takes_the_body_it_draws() {
    let _g = serial();
    assert_agree(&variants(), place, |c, at, x, y| c.hit(at, x, y));
}

#[test]
fn card_content_lies_in_the_box_clear_of_the_head_text() {
    let _g = serial();
    for (name, c) in variants() {
        let at = place(c.size())[1];
        let content = c.content(at);
        assert!(within(content, at), "{name}: {content:?} outside {at:?}");
        let draw = |c: Card| Canvas::new(at, 0).painted(|fb| c.draw(fb, at));
        let bare = draw(Card::new().title("").note(""));
        let head = draw(c).diff(&bare);
        let over = head.iter().find(|&&(x, y)| within(Rect { x, y, w: 1, h: 1 }, content));
        assert!(over.is_none(), "{name}: head text at {over:?} in content {content:?}");
    }
}
