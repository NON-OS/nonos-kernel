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

use crate::browser::net::mixnet::{leave_spare, new_tick, SPARE};
use crate::browser::shell::Shell;
use crate::browser::state::State;
use crate::browser::tab_scope::swap;
use crate::browser::tabs::{Tabs, MAX_TABS};
use crate::browser::ui::tab_turn::next_busy;

/* Every tab with a load in flight keeps loading. Each tick steps the tab
 * in view, then one busy tab out of view in turn, under one budget for
 * calls to the proxies. True when the tab in view has something to show. */
pub(super) fn tick_tabs(tabs: &mut Tabs, shell: &mut Shell, cursor: &mut usize) -> bool {
    new_tick();
    let shown = super::tick::tick_body(tabs.active_mut(), shell);
    let n = tabs.list.len();
    let mut busy = [false; MAX_TABS];
    for (i, s) in tabs.list.iter().enumerate() {
        busy[i] = i != tabs.active && s.loading();
    }
    if let Some(i) = next_busy(*cursor % n, &busy[..n]) {
        out_of_view(&mut tabs.list[i], shell);
        *cursor = i + 1;
    }
    let listed = super::downloads::tick(tabs, shell);
    shown || listed
}

/* A tab out of view steps with its own route, jar and faces in the
 * globals, and leaves streams at each proxy for the tab in view. */
fn out_of_view(s: &mut State, shell: &mut Shell) {
    swap(&mut s.scope);
    leave_spare(SPARE);
    super::tick::step(s, shell);
    leave_spare(0);
    swap(&mut s.scope);
}
