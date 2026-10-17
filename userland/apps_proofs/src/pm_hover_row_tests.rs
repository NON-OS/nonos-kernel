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

//! A move inside one table row, filter chip, the search field or End Process
//! asks for no repaint and a move off it asks for one, and the scroll shifts
//! the pointer as it shifts a click.

use nonos_app_skeleton::EventOutcome::{Idle, Repaint};

use crate::metrics::{CHIP_H, ROW_H, WIN_H, WIN_W};
use crate::pm::state::{Screen, FILTERS};
use crate::pm::ui::fit::inspector;
use crate::pm::ui::hit::Target;
use crate::pm::ui::hover::hover_to;
use crate::pm::ui::pane_geom::{pane_rect, table_rect};
use crate::pm::ui::table_geom::{row_y, visible_rows};
use crate::pm::ui::{chips, insp_geom, search};
use crate::pm_hover_tests::{at, window};

#[test]
fn a_move_inside_a_table_row_repaints_nothing_and_one_to_the_next_repaints() {
    for (screen, scroll) in [(Screen::Processes, 0), (Screen::Processes, 3), (Screen::Overview, 5)]
    {
        let state = window(screen, scroll);
        let pane = pane_rect(WIN_W, WIN_H, inspector(screen, WIN_W));
        let t = if screen == Screen::Overview { table_rect(&pane) } else { pane };
        for slot in 0..visible_rows(t.h) - 1 {
            let y = t.y + row_y(slot);
            let mut hover = at(&state, t.x, y);
            assert!(hover == Some(Target::Row(scroll + slot)));
            assert!(hover_to(&mut hover, at(&state, t.x + t.w - 1, y + ROW_H - 1)) == Idle);
            assert!(hover_to(&mut hover, at(&state, t.x, y + ROW_H)) == Repaint);
            assert!(hover == Some(Target::Row(scroll + slot + 1)));
        }
    }
}

#[test]
fn a_move_inside_a_chip_or_a_box_repaints_nothing_and_one_off_it_repaints() {
    let state = window(Screen::Processes, 0);
    let x0 = chips::origin(WIN_W, Screen::Processes).unwrap();
    let y = (0..WIN_H).find(|&y| at(&state, x0, y).is_some()).unwrap();
    let chip = |t| {
        let xs: Vec<u32> = (0..WIN_W).filter(|&x| at(&state, x, y) == Some(t)).collect();
        assert!(xs.len() as u32 == xs[xs.len() - 1] - xs[0] + 1);
        ((xs[0], y, xs.len() as u32, CHIP_H), t)
    };
    let mut boxes: Vec<_> = FILTERS.iter().map(|f| chip(Target::Filter(*f))).collect();
    boxes.push((search::rect(WIN_W, Screen::Processes), Target::Search));
    boxes.push((insp_geom::btn(WIN_W, WIN_H), Target::EndProcess));
    for ((x, y, w, h), t) in boxes {
        let mut hover = at(&state, x, y);
        assert!(hover == Some(t));
        assert!(hover_to(&mut hover, at(&state, x + w - 1, y + h - 1)) == Idle);
        assert!(hover_to(&mut hover, at(&state, x + w, y)) == Repaint && hover != Some(t));
    }
}
