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

//! Pill: the label reads on the pill in every tone and state, in `text` with
//! a dot or for `Plain` and in the tone without one, and the dot reads as a
//! non-text mark at 3:1. An accent label is `accent_text`, held to 4.5:1.

use nonos_toolkit::widgets::Pill;

use super::hide::Hide;
use super::legible::{assert_legible, Off, Read};
use super::pill::TONES;
use super::serial::serial;
use crate::wcag::{BODY, LARGE};

const LABEL: &str = "Grüße — 日本語";

/// For each tone in `TONES` order: its label alone, its label beside a dot,
/// and its dot.
const NAMES: [[&str; 3]; 5] = [
    ["plain label", "plain label by dot", "plain dot"],
    ["accent label", "accent label by dot", "accent dot"],
    ["ok label", "ok label by dot", "ok dot"],
    ["warn label", "warn label by dot", "warn dot"],
    ["danger label", "danger label by dot", "danger dot"],
];

#[test]
fn pill_label_and_dot_read_in_every_tone_and_state() {
    let _g = serial();
    let mut reads = Vec::new();
    for ((_, tone), [alone, by_dot, dot]) in TONES.into_iter().zip(NAMES) {
        let pill = Pill::new(LABEL).tone(tone);
        let text = || Off::Hide(Hide::Text(LABEL));
        reads.push(Read { what: alone, on: pill, off: text(), floor: BODY });
        reads.push(Read { what: by_dot, on: pill.dot(), off: text(), floor: BODY });
        reads.push(Read { what: dot, on: pill.dot(), off: Off::Hide(Hide::Dots), floor: LARGE });
    }
    assert_legible(&reads);
}
