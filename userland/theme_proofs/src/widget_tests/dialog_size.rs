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

//! Dialog: the panel grows with its text up to `DIALOG_W`; a body takes at
//! most `DIALOG_LINES` lines, the last cut with `…` only when more would
//! follow; and the note is drawn whole when it fits and cut when it does
//! not.

use nonos_toolkit::design::scale::{scale, set_scale};
use nonos_toolkit::design::size::{DIALOG_LINES, DIALOG_W};
use nonos_toolkit::widgets::{Dialog, Rect, Tone};

use super::boxes::boxes;
use super::dialog::{BODIES, NOTE, OVER, THREE};
use super::serial::{serial, SCALES};
use super::toast_lines::Runs;

/// The runs of text `d` draws in `at`, in order: title, body, note, labels.
fn runs(d: Dialog, at: Rect) -> Vec<String> {
    let mut runs = Runs(Vec::new());
    d.draw(&mut runs, at);
    runs.0
}

/// Per body: its lines, whether the last is cut, and whether the panel
/// takes its cap.
const WANT: [(usize, bool, bool); 4] =
    [(1, false, false), (2, false, true), (DIALOG_LINES as usize, true, true), (1, false, false)];

#[test]
fn dialog_body_takes_its_lines_and_the_panel_stops_at_its_cap() {
    let _g = serial();
    let mut fails = Vec::new();
    for q in SCALES {
        set_scale(q);
        let cap = scale().px(DIALOG_W);
        for (body, want) in BODIES.into_iter().zip(WANT) {
            let d = Dialog::new("Delete?").body(body).buttons(THREE);
            let (w, all) = (d.size().0, runs(d, boxes(d.size())[0]));
            let lines = &all[1..all.len() - THREE.len()];
            let got = (lines.len(), lines.last().is_some_and(|l| l.ends_with('…')), w == cap);
            if got != want || w > cap {
                fails.push(format!("{body:?} at {q}/4, {w} wide: {lines:?}"));
            }
        }
        let d = |note| Dialog::new("Install?").note(note, Tone::Warn);
        let note = |note| runs(d(note), boxes(d(note).size())[0]).pop().unwrap_or_default();
        if note(NOTE) != NOTE || !note(OVER).ends_with('…') {
            fails.push(format!("notes at {q}/4: {:?}, {:?}", note(NOTE), note(OVER)));
        }
    }
    set_scale(SCALES[0]);
    assert!(fails.is_empty(), "{} cases\n{}", fails.len(), fails.join("\n"));
}
