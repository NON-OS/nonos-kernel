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

//! Toast: every tone, with and without an action, with one-line, two-line,
//! over-long and multi-byte text, stays in its box in every state at every
//! scale, in boxes its own size, wider and narrower, and in boxes shorter
//! than itself.

use nonos_toolkit::widgets::Toast;

use super::bounds::{assert_bounded, assert_bounded_in};
use super::boxes::boxed;
use super::pill::TONES;
use super::samples::LONG;
use super::serial::serial;

/// A text that takes two lines in a toast at its widest.
pub(crate) const TWO: &str = "The download finished and the file is now in Documents";

/// A text that takes more than two lines in every box the proofs give, so
/// the second is cut.
pub(crate) const OVER: &str = "Ein sehr langer Hinweis über 日本語 und Grüße, der in zwei \
    Zeilen nicht passt, weil er immer weiter geht und kein Ende findet, auch dann nicht, \
    wenn der Kasten breiter wird als der Toast selbst, denn er geht immer noch weiter";

/// The texts the proofs show: one line, two lines, over-long and multi-byte.
pub(crate) const TEXTS: [&str; 4] = ["Saved", TWO, OVER, "Grüße — 日本語"];

/// The actions the proofs give: none, short, and too long for any toast.
pub(crate) const ACTIONS: [&str; 3] = ["", "Undo", LONG];

fn variants() -> Vec<(String, Toast<'static>)> {
    let mut all = Vec::new();
    for (name, tone) in TONES {
        for text in TEXTS {
            for action in ACTIONS {
                let t = Toast::new(text).tone(tone).action(action);
                all.push((format!("{name} {text:?} action {action:?}"), t));
            }
        }
    }
    all
}

#[test]
fn toast_paints_inside_its_box() {
    let _g = serial();
    assert_bounded(&variants());
}

#[test]
fn toast_paints_inside_a_box_shorter_than_itself() {
    let _g = serial();
    let short =
        |(w, h): (u32, u32)| [boxed(w, h - 1), boxed(w, h / 2), boxed(w / 3, 2), boxed(1, 1)];
    assert_bounded_in(&variants(), short);
}
