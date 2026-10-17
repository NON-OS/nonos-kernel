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

//! Menu: nowhere is a separator or a disabled item hit, nor the padding at
//! the panel's top and sides, nor any point off the menu, nor any point of a
//! disabled menu.

use nonos_toolkit::design::scale::set_scale;
use nonos_toolkit::widgets::{Item, Menu, Rect, State};

use super::boxes::boxes;
use super::hits::around;
use super::menu::MENUS;
use super::serial::{serial, SCALES};

/// Points every 7 px across and 3 px down `at`, then the points just inside
/// its top, left and right edges, which are padding, and points round it.
fn probes(at: Rect) -> [Vec<(i32, i32)>; 2] {
    let (x0, y0, x1) = (at.x as i32, at.y as i32, (at.x + at.w) as i32 - 1);
    let ys = y0..y0 + at.h as i32;
    let grid = ys.clone().step_by(3).flat_map(|y| (x0..=x1).step_by(7).map(move |x| (x, y)));
    let pad = (x0..=x1).map(|x| (x, y0 + 1)).chain(ys.flat_map(|y| [(x0 + 1, y), (x1 - 1, y)]));
    [grid.collect(), pad.chain(around(at)).collect()]
}

/// A line for the first probe that hits a dead item, the padding, or a
/// point off the menu, or that hits anything once the menu is disabled.
fn wrongly_hit(m: Menu, items: &[Item], at: Rect) -> Option<String> {
    let [grid, off] = probes(at);
    let off_m = m.state(State { disabled: true, ..State::default() });
    let dead = |&&(x, y): &&(i32, i32)| m.hit(at, x, y).is_some_and(|i| !items[i].live());
    let bad = grid.iter().find(dead).or(off.iter().find(|&&(x, y)| m.hit(at, x, y).is_some()));
    let bad = bad.or(grid.iter().chain(&off).find(|&&(x, y)| off_m.hit(at, x, y).is_some()));
    bad.map(|&(x, y)| format!("in {at:?}: {x}, {y} hits {:?}", m.hit(at, x, y)))
}

#[test]
fn menu_hit_is_never_a_dead_row_padding_or_off_the_menu() {
    let _g = serial();
    let mut fails = Vec::new();
    for q in SCALES {
        set_scale(q);
        for (name, items) in MENUS {
            let m = Menu::new(items);
            for at in boxes(m.size()) {
                fails.extend(wrongly_hit(m, items, at).map(|e| format!("{name} at {q}/4 {e}")));
            }
        }
    }
    set_scale(SCALES[0]);
    assert!(fails.is_empty(), "{} cases\n{}", fails.len(), fails.join("\n"));
}
