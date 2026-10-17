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

//! Toast: in every tone, with and without an action, and in every live state,
//! the text reads on the panel as body text at 4.5:1, whole or cut with `…`,
//! the bar reads on it as a non-text mark at 3:1 and the action's label as
//! body text at 4.5:1, in every scheme and high contrast, read back from the
//! pixels drawn. Disabled need only be drawn visibly.

use nonos_toolkit::widgets::{Toast, Tone};

use super::hide::Hide;
use super::legible::{assert_legible, Off, Read};
use super::pill::TONES;
use super::serial::serial;
use super::toast::OVER;
use crate::wcag::{BODY, LARGE};

const LABEL: &str = "Grüße — 日本語";
const ACTION: &str = "Rückgängig";

/// The fill the bar is painted with: after the shadow and the panel.
const BAR: Hide = Hide::Round(2);

fn reads((name, tone): (&str, Tone)) -> [Read<Toast<'static>>; 7] {
    let what = |part: &str| -> &'static str { format!("{name} {part}").leak() };
    let t = |text: &'static str, action| Toast::new(text).tone(tone).action(action);
    let read = |what, on, off, floor| Read { what, on, off, floor };
    let (bare, acted) = (|| Off::Widget(t("", "")), || Off::Widget(t("", ACTION)));
    [
        read(what("text"), t(LABEL, ""), bare(), BODY),
        read(what("cut text"), t(OVER, ""), bare(), BODY),
        read(what("text by action"), t(LABEL, ACTION), acted(), BODY),
        read(what("cut text by action"), t(OVER, ACTION), acted(), BODY),
        read(what("bar"), t(LABEL, ""), Off::Hide(BAR), LARGE),
        read(what("bar by action"), t(OVER, ACTION), Off::Hide(BAR), LARGE),
        read(what("action"), t(LABEL, ACTION), Off::Hide(Hide::Text(ACTION)), BODY),
    ]
}

#[test]
fn toast_text_bar_and_action_read_in_every_tone_and_state() {
    let _g = serial();
    let all: Vec<_> = TONES.into_iter().flat_map(reads).collect();
    assert_legible(&all);
}
