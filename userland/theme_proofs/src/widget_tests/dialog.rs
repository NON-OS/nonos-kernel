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

//! The dialogs the Dialog proofs draw: short, multi-line, over-long and
//! multi-byte bodies, with and without a note, under no, one, two and three
//! buttons, a Danger one among them, and two too wide for the row.

use nonos_toolkit::widgets::{Dialog, Kind, Tone};

use super::samples::LONG;

/// A set of buttons, as `Dialog::buttons` takes them.
pub(crate) type Buttons = &'static [(&'static str, Kind)];

/// A body longer than `DIALOG_LINES` lines at the widest, so it is cut.
pub(crate) const OVER: &str = "Ein sehr langer Hinweis über 日本語 und Grüße, der in fünf \
    Zeilen nicht passt, weil er immer weiter geht und kein Ende findet, auch dann nicht, \
    wenn der Kasten breiter wird als der Dialog selbst, denn er geht immer noch weiter, \
    Zeile um Zeile, Wort um Wort, bis auch die fünfte Zeile voll ist und noch mehr folgt, \
    und danach kommt noch eine ganze Menge mehr, damit sicher etwas abgeschnitten wird.";

/// Short, two lines, over-long and multi-byte.
pub(crate) const BODIES: [&str; 4] = [
    "It cannot be undone.",
    "The file is removed from your desktop. There is no Trash to get it back from.",
    OVER,
    "Grüße — 日本語 🙂 naïve café",
];

/// The pkg consent's warning line.
pub(crate) const NOTE: &str = "! caps hidden - do not approve";

/// Three buttons, the last a Danger one.
pub(crate) const THREE: Buttons =
    &[("Später", Kind::Plain), ("Abbrechen", Kind::Secondary), ("Löschen", Kind::Danger)];

/// No button, one, two, three, and two too wide for any row.
pub(crate) const SETS: [Buttons; 5] = [
    &[],
    &[("OK", Kind::Primary)],
    &[("Cancel", Kind::Secondary), ("Approve", Kind::Primary)],
    THREE,
    &[(LONG, Kind::Secondary), (LONG, Kind::Danger)],
];

/// Every body under every set, the note on every other one in a tone and a
/// long title on every third, with button `k` of 4 focused, the next
/// hovered and the one after held, so some fall past the last button.
pub(crate) fn dialogs() -> Vec<(String, Dialog<'static>)> {
    let each = BODIES.into_iter().flat_map(|b| SETS.map(|s| (b, s))).enumerate();
    let tone = |k: usize| [Tone::Warn, Tone::Danger, Tone::Accent][k % 3];
    let dialog = |(k, (body, set)): (usize, (&'static str, Buttons))| {
        let title = if k % 3 == 2 { LONG } else { "Install package?" };
        let d = Dialog::new(title).body(body).buttons(set).focus(k % 4);
        let d = d.hovered(Some((k + 1) % 4)).pressed(Some((k + 2) % 4));
        let d = if k % 2 == 0 { d.note(NOTE, tone(k / 2)) } else { d };
        (format!("{body:?} under {set:?} {k}"), d)
    };
    each.map(dialog).collect()
}
