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

//! The inks the Dialog readability proof reads: the title, the body whole
//! and cut, the note in every tone, and one button of each kind lit every
//! way, each with the mark hidden that it is read against.

use nonos_toolkit::widgets::{Dialog, Kind};

use super::dialog::{BODIES, NOTE, OVER};
use super::hide::Hide;
use super::pill::TONES;
use super::read::{Off, Read};
use crate::wcag::BODY;

const TITLE: &str = "Paket installieren?";

/// One button of each kind.
const FOUR: [(&str, Kind); 4] = [
    ("Später", Kind::Plain),
    ("Nein", Kind::Secondary),
    ("Löschen", Kind::Danger),
    ("Öffnen", Kind::Primary),
];

/// The dialog the inks are read in, with `body` under the title.
fn dialog(body: &'static str) -> Dialog<'static> {
    Dialog::new(TITLE).body(body).note(NOTE, TONES[3].1).buttons(&FOUR)
}

/// Button `i` lit plain, hovered, pressed, held, focused, and all of these.
fn lit(i: usize) -> Vec<(&'static str, Dialog<'static>)> {
    let (d, on) = (dialog(BODIES[1]), Some(i));
    let held = d.hovered(on).pressed(on);
    let pointer = [("plain", d), ("hovered", d.hovered(on)), ("pressed", d.pressed(on))];
    [pointer, [("held", held), ("focused", d.focus(i)), ("all", held.focus(i))]].concat()
}

/// Every ink, each with the dialog it is read in, the mark hidden, and
/// whether it is read disabled too.
pub(crate) fn reads() -> Vec<(Read<Dialog<'static>>, bool)> {
    let read = |what: String, on, hide, off| {
        (Read { what: what.leak(), on, off: Off::Hide(hide), floor: BODY }, off)
    };
    let mut all = vec![
        read("title".into(), dialog(BODIES[1]), Hide::Text(TITLE), true),
        read("body".into(), dialog(BODIES[1]), Hide::Within(BODIES[1]), true),
        read("cut body".into(), dialog(OVER), Hide::Within(OVER), false),
    ];
    for (k, (name, tone)) in TONES.into_iter().enumerate() {
        let d = dialog(BODIES[1]).note(NOTE, tone);
        all.push(read(format!("{name} note"), d, Hide::Text(NOTE), k == 0));
    }
    for (i, (label, _)) in FOUR.into_iter().enumerate() {
        for (k, (look, d)) in lit(i).into_iter().enumerate() {
            all.push(read(format!("{look} {label}"), d, Hide::Text(label), k == 0));
        }
    }
    all
}
