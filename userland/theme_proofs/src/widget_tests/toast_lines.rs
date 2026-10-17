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

//! Toast: the text takes one line or two, never more, the second cut with
//! `…` when the rest would not fit, in every box; and no toast is wider than
//! `TOAST_W` or shorter than a button when it has an action.

use nonos_toolkit::design::scale::{scale, set_scale};
use nonos_toolkit::design::size::TOAST_W;
use nonos_toolkit::icons::IconId;
use nonos_toolkit::paint::measure_ttf;
use nonos_toolkit::widgets::{Button, Surface, Toast};

use super::boxes::boxes;
use super::serial::{serial, SCALES};
use super::toast::{OVER, TEXTS, TWO};

/// A surface that keeps the runs of text drawn on it and paints nothing.
pub(crate) struct Runs(pub(crate) Vec<String>);

impl Surface for Runs {
    fn fill_rect(&mut self, _: u32, _: u32, _: u32, _: u32, _: u32) {}
    fn blend_rect(&mut self, _: u32, _: u32, _: u32, _: u32, _: u32) {}
    fn fill_round(&mut self, _: u32, _: u32, _: u32, _: u32, _: u32, _: u32) {}
    fn stroke_round(&mut self, _: u32, _: u32, _: u32, _: u32, _: u32, _: u32, _: u32) {}
    fn circle(&mut self, _: u32, _: u32, _: u32, _: u32) {}
    fn text_ttf(&mut self, x: i32, _: i32, text: &str, _: u32, px: f32) -> i32 {
        self.0.push(text.to_string());
        x + measure_ttf(text, px)
    }
    fn icon(&mut self, _: IconId, _: u32, _: u32, _: u32, _: u32) {}
}

#[test]
fn toast_text_takes_at_most_two_lines_cut_after_the_second() {
    let _g = serial();
    let mut fails = Vec::new();
    for q in SCALES {
        set_scale(q);
        for text in TEXTS {
            let t = Toast::new(text);
            let want = if text == TWO || text == OVER { 2 } else { 1 };
            for (i, at) in boxes(t.size()).into_iter().enumerate() {
                let mut runs = Runs(Vec::new());
                t.draw(&mut runs, at);
                let (n, cut) = (runs.0.len(), runs.0.last().is_some_and(|r| r.ends_with('…')));
                let cut_ok = if text == OVER { cut } else { i > 1 || !cut };
                if !(1..=2).contains(&n) || (i == 0 && n != want) || !cut_ok {
                    fails.push(format!("{text:?} at {q}/4 in {at:?}: {:?}", runs.0));
                }
            }
        }
        let (cap, tall) = (scale().px(TOAST_W), Button::new("Undo").size().1);
        for (w, h) in TEXTS.map(|text| Toast::new(text).action("Undo").size()) {
            if w > cap || h <= tall || Toast::new(OVER).size().0 != cap {
                fails.push(format!("at {q}/4: {w} by {h}, over {cap} or under {tall}"));
            }
        }
    }
    set_scale(SCALES[0]);
    assert!(fails.is_empty(), "{} cases\n{}", fails.len(), fails.join("\n"));
}
