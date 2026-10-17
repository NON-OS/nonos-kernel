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

//! Menu: on a plain, hovered, pressed and held row, the label reads as body
//! text at 4.5:1, whole or cut with `…`, the muted shortcut at 4.5:1 too and
//! the tick at 3:1, in every scheme and high contrast, read back from the
//! pixels drawn. A separator and a disabled item, and every row of a
//! disabled menu, need only be drawn visibly.

use nonos_toolkit::widgets::{Item, Menu, State};

use super::hide::Hide;
use super::legible::{assert_legible_in, Off, Read, NONE};
use super::samples::LONG;
use super::serial::serial;
use crate::wcag::{BODY, LARGE};

const LABEL: &str = "Grüße — 日本語";
const KEYS: &str = "Strg+Ü";
const OFF: &str = "Löschen";
const OFF_KEYS: &str = "Entf";

/// A ticked item with keys, a separator, a disabled item and a long one.
static ITEMS: [Item; 4] = [
    Item::new(LABEL).shortcut(KEYS).checked(true),
    Item::separator(),
    Item::new(OFF).shortcut(OFF_KEYS).disabled(),
    Item::new(LONG).shortcut("Ctrl+Q"),
];

/// The menu with no row lit, then row `i` hovered, pressed, and both.
fn lit(i: usize) -> [(&'static str, Menu<'static>); 4] {
    let m = Menu::new(&ITEMS);
    let (h, p) = (m.hovered(Some(i)), m.pressed(Some(i)));
    [("plain", m), ("hovered", h), ("pressed", p), ("held", h.pressed(Some(i)))]
}

/// Every ink to read. With no row lit, the separator's hairline is the third
/// fill painted, after the shadow and the panel.
fn reads() -> Vec<Read<Menu<'static>>> {
    let read =
        |what: String, on, hide, floor| Read { what: what.leak(), on, off: Off::Hide(hide), floor };
    let mut all = Vec::new();
    for ((row, on), (_, long)) in lit(0).into_iter().zip(lit(3)) {
        all.push(read(format!("{row} label"), on, Hide::Text(LABEL), BODY));
        all.push(read(format!("{row} shortcut"), on, Hide::Text(KEYS), BODY));
        all.push(read(format!("{row} tick"), on, Hide::Dots, LARGE));
        all.push(read(format!("{row} cut label"), long, Hide::Text(LONG), BODY));
    }
    let m = Menu::new(&ITEMS);
    all.push(read("separator".into(), m, Hide::Round(2), NONE));
    all.push(read("disabled label".into(), m, Hide::Text(OFF), NONE));
    all.push(read("disabled shortcut".into(), m, Hide::Text(OFF_KEYS), NONE));
    all
}

#[test]
fn menu_labels_shortcuts_and_ticks_read_on_every_row() {
    let _g = serial();
    let off = State { disabled: true, ..State::default() };
    assert_legible_in(&reads(), || [State::default(), off].into_iter());
}
