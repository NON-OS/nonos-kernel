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

//! What the pointer hovers in the process monitor's sidebar: a move inside
//! one entry asks for no repaint and a move to the next asks for one. The
//! window the other hover proofs read is set up here.

use nonos_app_skeleton::EventOutcome::{Idle, Repaint};
use nonos_toolkit::widgets::Pointer;

use crate::metrics::{NAV_H, WIN_H, WIN_W};
use crate::pm::state::{Filter, Row, Screen, State, SCREENS};
use crate::pm::ui::hit::Target;
use crate::pm::ui::hover::{hover_to, target_at};
use crate::pm::ui::nav_geom::{row_w, row_x, row_y};

/// Forty processes and four findings on `screen` at `scroll`, in the window
/// the capsule opens.
pub(crate) fn window(screen: Screen, scroll: usize) -> State {
    State {
        rows: (0..40).map(|i| Row { pid: i + 100, caps: 0, name: b"app" }).collect(),
        filter: Filter::All,
        flagged: Vec::new(),
        me: 0,
        selected_pid: 0,
        scroll,
        screen,
        alerts: vec![(); 4],
        alert_scroll: 0,
        fb_w: WIN_W,
        fb_h: WIN_H,
        pointer: Pointer::new(),
        hover: None,
    }
}

pub(crate) fn at(state: &State, x: u32, y: u32) -> Option<Target> {
    target_at(state, x as i32, y as i32)
}

#[test]
fn a_move_inside_a_nav_entry_repaints_nothing_and_one_to_the_next_repaints() {
    let state = window(Screen::Overview, 0);
    let (x0, x1) = (row_x(), row_x() + row_w(WIN_W) - 1);
    for i in 0..SCREENS.len() - 1 {
        let mut hover = at(&state, x0, row_y(i));
        assert!(hover == Some(Target::Nav(SCREENS[i])));
        assert!(hover_to(&mut hover, at(&state, x1, row_y(i) + NAV_H - 1)) == Idle);
        assert!(hover_to(&mut hover, at(&state, x0, row_y(i + 1))) == Repaint);
        assert!(hover == Some(Target::Nav(SCREENS[i + 1])));
    }
}
