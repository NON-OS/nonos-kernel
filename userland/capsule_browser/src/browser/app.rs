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

use nonos_app_skeleton::{App, AppManifest, EventOutcome, InputEvent, PaintBuffer};
use nonos_toolkit::decorations::Rect;

use super::event::on_event;
use super::manifest::manifest;
use super::shell::Shell;
use super::state::State;

mod damage;
mod nav;
mod paint;
mod print;
mod pumps;
mod tick;
mod visits;

/* `state` is the page; `shell` the window around it: sidebar, start page,
 * visit log and bookmarks. */
pub struct Browser {
    state: State,
    shell: Shell,
}

impl Browser {
    pub fn new() -> Self {
        Browser { state: State::new(), shell: Shell::default() }
    }
}

impl App for Browser {
    fn manifest(&self) -> AppManifest {
        manifest()
    }
    fn on_event(&mut self, event: InputEvent) -> EventOutcome {
        on_event(&mut self.state, &mut self.shell, event)
    }
    fn paint(&mut self, fb: &mut PaintBuffer) {
        paint::paint_app(&mut self.state, &self.shell, fb);
    }
    fn on_tick(&mut self) -> bool {
        tick::tick_body(&mut self.state, &mut self.shell)
    }

    fn tick_interval_ms(&self) -> i64 {
        50
    }

    /* A request on the wire, a queued navigation, or stylesheets, images or
     * fonts still to fetch all mean the load must keep stepping. Reporting busy
     * makes the runner yield rather than sleep, so the page advances through its
     * fetch stages on its own instead of stalling until the pointer moves. */
    fn busy(&self) -> bool {
        self.state.loading()
    }

    fn take_damage(&mut self) -> Option<Rect> {
        damage::take(&mut self.state)
    }
}
