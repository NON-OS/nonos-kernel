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

//! Menu: `next` walks the live items in order, down or up, wrapping round
//! the ends and stepping over separators and disabled items, from no row,
//! a live row, a dead row or an index past the end, by any step. With no
//! live item it gives `None`.

use std::iter::successors;

use nonos_toolkit::widgets::{Item, Menu};

use super::menu::{FULL, RULES};

/// The live items of `FULL`, in order.
const LIVE: [usize; 4] = [0, 3, 4, 7];

#[test]
fn menu_next_walks_the_live_items_and_wraps() {
    let walk = |step| {
        let next = |at: &usize| Menu::next(&FULL, Some(*at), step);
        successors(Menu::next(&FULL, None, step), next).take(9).collect::<Vec<_>>()
    };
    assert_eq!(walk(1), (0..9).map(|i| LIVE[i % 4]).collect::<Vec<_>>(), "down");
    assert_eq!(walk(-1), (0..9).map(|i| LIVE[3 - i % 4]).collect::<Vec<_>>(), "up");
}

#[test]
fn menu_next_steps_from_any_row_by_any_step() {
    let next = |from, step| Menu::next(&FULL, from, step);
    assert_eq!(next(Some(0), 2), Some(4), "two down");
    assert_eq!(next(Some(0), -1), Some(7), "up past the top");
    assert_eq!(next(Some(7), 1), Some(0), "down past the bottom");
    assert_eq!(next(Some(2), 1), Some(3), "down from a separator");
    assert_eq!(next(Some(2), -1), Some(0), "up from a separator");
    assert_eq!(next(Some(1), 1), Some(3), "down from a disabled item");
    assert_eq!(next(Some(99), 1), Some(0), "down from past the end");
    assert_eq!(next(Some(99), -1), Some(7), "up from past the end");
    assert_eq!((next(Some(3), 0), next(Some(1), 0), next(None, 0)), (Some(3), None, None));
    assert_eq!(
        (next(Some(0), 4), next(Some(0), 5), next(Some(0), -5)),
        (Some(0), Some(3), Some(7))
    );
    for from in [None, Some(0), Some(2), Some(5), Some(8), Some(99)] {
        for step in (-9..=9).chain([i32::MIN, i32::MAX]).filter(|&s| s != 0) {
            let got = next(from, step);
            assert!(got.is_some_and(|i| FULL[i].live()), "{from:?} by {step}: {got:?}");
        }
    }
}

#[test]
fn menu_next_finds_nothing_with_no_live_item() {
    let off = [Item::new("Cut").disabled(), Item::separator(), Item::new("Copy").disabled()];
    for items in [&RULES[..], &off[..], &[]] {
        for from in [None, Some(0), Some(1), Some(5)] {
            for step in [-2, -1, 0, 1, 2, i32::MIN, i32::MAX] {
                assert_eq!(Menu::next(items, from, step), None, "{items:?} {from:?} by {step}");
            }
        }
    }
}
