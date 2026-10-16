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

//! Progress: every share and tone stays in the box, and the fill is drawn
//! visibly on its track. colours.md holds a fill on the track to no floor.

use nonos_toolkit::widgets::Progress;

use super::bounds::assert_bounded;
use super::hide::Hide;
use super::legible::{assert_legible, Off, Read, NONE};
use super::pill::TONES;
use super::serial::serial;

fn variants() -> Vec<(String, Progress)> {
    let mut all = Vec::new();
    for (name, tone) in TONES {
        for (done, total) in [(0, 10), (5, 10), (10, 10), (12, 10), (7, 0), (1, 3)] {
            all.push((format!("{name} {done} of {total}"), Progress::new(done, total).tone(tone)));
        }
    }
    all
}

#[test]
fn progress_paints_inside_its_box() {
    let _g = serial();
    assert_bounded(&variants());
}

#[test]
fn progress_fill_is_drawn_visibly_in_every_tone() {
    let _g = serial();
    let read = |(what, tone)| Read {
        what,
        on: Progress::new(1, 2).tone(tone),
        off: Off::Hide(Hide::Round(1)),
        floor: NONE,
    };
    assert_legible(&TONES.map(read));
}
