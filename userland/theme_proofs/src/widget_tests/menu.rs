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

//! Menu: plain labels, shortcuts, separators, disabled and checked items,
//! and long and multi-byte labels stay in the box with no row lit, a row
//! hovered, pressed or both, a disabled row hovered and a lit index past the
//! end, in every state at every scale, in boxes its own size, wider and
//! narrower, and shorter.

use nonos_toolkit::widgets::{Item, Menu};

use super::bounds::{assert_bounded, assert_bounded_in};
use super::boxes::boxed;
use super::samples::LONG;
use super::serial::serial;

/// Labels only.
const PLAIN: [Item; 3] = [Item::new("Open"), Item::new("Save"), Item::new("Close")];

/// Live index 0, 3, 4 and 7 among a disabled item, separators, ticks on and
/// off, a disabled ticked item and a multi-byte label and shortcut.
pub(crate) const FULL: [Item; 8] = [
    Item::new("Undo").shortcut("Ctrl+Z"),
    Item::new("Redo").shortcut("Ctrl+Shift+Z").disabled(),
    Item::separator(),
    Item::new("Word wrap").checked(true),
    Item::new("Line numbers").checked(false),
    Item::new("Spell check").checked(true).disabled(),
    Item::separator(),
    Item::new("Grüße — 日本語").shortcut("Strg+Ü"),
];

/// Labels and a shortcut too long for any menu, so each is cut.
const LONGS: [Item; 3] = [Item::new(LONG).shortcut(LONG), Item::new(LONG), Item::new("Quit")];

/// Separators only, so nothing is live.
pub(crate) const RULES: [Item; 2] = [Item::separator(), Item::separator()];

/// The menus the proofs draw, by name.
pub(crate) const MENUS: [(&str, &[Item]); 4] =
    [("plain", &PLAIN), ("full", &FULL), ("long", &LONGS), ("rules", &RULES)];

fn variants() -> Vec<(String, Menu<'static>)> {
    let lit = [(None, None), (Some(0), Some(0)), (Some(1), None), (None, Some(7))];
    let each = MENUS.into_iter().flat_map(|(name, items)| lit.map(move |l| (name, items, l)));
    let menu = |items, (h, p)| Menu::new(items).hovered(h).pressed(p);
    each.map(|(name, items, l)| (format!("{name} lit {l:?}"), menu(items, l))).collect()
}

#[test]
fn menu_paints_inside_its_box() {
    let _g = serial();
    assert_bounded(&variants());
}

#[test]
fn menu_paints_inside_a_box_shorter_than_itself() {
    let _g = serial();
    let short =
        |(w, h): (u32, u32)| [boxed(w, h - 1), boxed(w, h / 2), boxed(w / 3, 2), boxed(1, 1)];
    assert_bounded_in(&variants(), short);
}
