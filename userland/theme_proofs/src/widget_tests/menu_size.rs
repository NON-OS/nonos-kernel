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

//! Menu: its height adds up `MENU_ROW_H` per item, `SPACE.sm` per separator,
//! `SPACE.xs` above and below and the shadow's drop. Its width grows with the
//! widest label, the widest shortcut and the tick's room, stops at
//! `MENU_MAX_W`, and is exactly what `.width` sets.

use nonos_toolkit::design::scale::{scale, set_scale};
use nonos_toolkit::design::size::{ICON, MENU_MAX_W, MENU_ROW_H, SPACE};
use nonos_toolkit::widgets::{Item, Menu};

use super::menu::MENUS;
use super::samples::LONG;
use super::serial::{serial, SCALES};

#[test]
fn menu_height_adds_up_its_rows() {
    let _g = serial();
    for q in SCALES {
        set_scale(q);
        let s = scale();
        let (row, sep) = (s.px(MENU_ROW_H), s.px(u32::from(SPACE.sm)));
        let ends = s.px(u32::from(SPACE.xs)) * 2 + s.hair() * 2;
        for (name, items) in MENUS {
            let seps = items.iter().filter(|it| **it == Item::separator()).count() as u32;
            let want = (items.len() as u32 - seps) * row + seps * sep + ends;
            assert_eq!(Menu::new(items).size().1, want, "{name} at {q}/4");
        }
    }
    set_scale(SCALES[0]);
}

#[test]
fn menu_width_follows_its_widest_row_up_to_its_cap() {
    let _g = serial();
    let w = |items: &[Item]| Menu::new(items).size().0;
    for q in SCALES {
        set_scale(q);
        let s = scale();
        let (cap, undo) = (s.px(MENU_MAX_W), w(&[Item::new("Undo")]));
        assert_eq!(w(&[Item::new(LONG)]), cap, "a long label at {q}/4");
        assert_eq!(w(&[Item::new("Undo").shortcut(LONG)]), cap, "long keys at {q}/4");
        assert!(undo < cap, "a short label at {q}/4");
        assert!(w(&[Item::new("Undo").shortcut("Ctrl+Z")]) > undo, "keys at {q}/4");
        assert!(w(&[Item::new("Grüße — 日本語")]) > w(&[Item::new("Grüße")]), "at {q}/4");
        let tick = s.px(ICON) + s.px(u32::from(SPACE.sm));
        assert_eq!(w(&[Item::new("Undo"), Item::new("A").checked(false)]), undo + tick, "{q}/4");
        assert_eq!(w(&[Item::separator()]), w(&[]), "a separator has no width at {q}/4");
        for want in [1, 123, 1000] {
            assert_eq!(Menu::new(&[Item::new(LONG)]).width(want).size().0, want, "at {q}/4");
        }
    }
    set_scale(SCALES[0]);
}
