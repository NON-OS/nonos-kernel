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
//! The clock's controls: what a click or a hover names is the control drawn
//! there, the buttons of one tab never overlap, and each tab of the strip
//! names itself.

use nonos_toolkit::widgets::rect::contains;

use crate::clock::controls::{keys, target_at, Target};
use crate::clock::tabs::{all, bar, strip, Tab};

const WIDTH: u32 = 360;

#[test]
fn every_button_is_named_by_the_point_at_its_centre() {
    for tab in all() {
        for (i, k) in keys(tab).iter().enumerate() {
            let (x, y) = ((k.x + k.w / 2) as i32, (k.y + k.h / 2) as i32);
            assert_eq!(target_at(tab, WIDTH, x, y), Some(Target::Key(i)));
        }
    }
}

#[test]
fn the_buttons_of_one_tab_never_overlap() {
    for tab in all() {
        let ks = keys(tab);
        for (i, a) in ks.iter().enumerate() {
            for b in &ks[i + 1..] {
                let corners = [(b.x, b.y), (b.x + b.w - 1, b.y), (b.x, b.y + b.h - 1)];
                assert!(!corners.iter().any(|&(x, y)| contains(*a, x as i32, y as i32)));
            }
        }
    }
}

#[test]
fn each_tab_of_the_strip_names_itself_and_nothing_names_a_tab_off_the_bar() {
    let b = bar(WIDTH);
    for tab in all() {
        let names: Vec<_> = (0..WIDTH as i32)
            .filter_map(|x| target_at(tab, WIDTH, x, (b.y + b.h / 2) as i32))
            .collect();
        for i in 0..all().len() {
            assert!(names.contains(&Target::Tab(i)), "{i} has no point on the bar");
        }
        assert_eq!(strip(tab).hit(b, 10, b.y as i32 - 1), None);
    }
}

#[test]
fn the_clock_tab_has_no_buttons_and_a_click_off_everything_names_nothing() {
    assert!(keys(Tab::Clock).is_empty());
    assert_eq!(target_at(Tab::Timer, WIDTH, 5, 440), None);
}
