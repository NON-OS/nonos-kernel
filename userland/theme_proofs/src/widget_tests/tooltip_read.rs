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

//! Tooltip: the text reads as body text at 4.5:1 on the tooltip's own box in
//! every scheme and high contrast, over every ground it can open on, whole or
//! cut with `…`; disabled need only be drawn visibly. The box is opaque under
//! the text, so the ground it opens over never shows through it.

use nonos_toolkit::widgets::Tooltip;

use super::canvas::Canvas;
use super::hide::Hide;
use super::legible::{assert_legible, Off, Read};
use super::mask::Masked;
use super::samples::LONG;
use super::serial::{per_theme, serial};
use super::widget::Widget;
use crate::wcag::BODY;

const LABEL: &str = "Grüße — 日本語";

/// Two grounds far apart, black and white, to see whether either shows.
const GROUNDS: [u32; 2] = [0xFF00_0000, 0xFFFF_FFFF];

#[test]
fn tooltip_text_reads_on_its_box_over_every_ground() {
    let _g = serial();
    let read = |what, text| Read {
        what,
        on: Tooltip::new(text),
        off: Off::Hide(Hide::Text(text)),
        floor: BODY,
    };
    assert_legible(&[read("text", LABEL), read("cut text", LONG)]);
}

#[test]
fn tooltip_box_hides_the_ground_round_its_text() {
    let _g = serial();
    let mut fails = Vec::new();
    per_theme(|theme| {
        let t = Tooltip::new(LABEL);
        let at = t.read_box();
        let lit = GROUNDS.map(|g| Canvas::new(at, g).painted(|fb| t.draw(fb, at)));
        let hide = Hide::Text(LABEL);
        let bare = Canvas::new(at, GROUNDS[0])
            .painted(|fb| t.draw(&mut Masked { fb, hide, rounds: 0 }, at));
        let ink = lit[0].diff(&bare);
        let span = |f: fn(&(u32, u32)) -> u32| ink.iter().map(f).min().zip(ink.iter().map(f).max());
        let (Some((x0, x1)), Some((y0, y1))) = (span(|p| p.0), span(|p| p.1)) else {
            fails.push(format!("{theme}: no text drawn"));
            return;
        };
        let line = (y0..=y1).flat_map(|y| (x0..=x1).map(move |x| (x, y)));
        let shows = line.filter(|&(x, y)| lit[0].get(x, y) != lit[1].get(x, y)).count();
        if shows > 0 {
            fails.push(format!("{theme}: the ground shows at {shows} pixels round the text"));
        }
    });
    assert!(fails.is_empty(), "{} cases\n{}", fails.len(), fails.join("\n"));
}
