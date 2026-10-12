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

use nonos_app_skeleton::{EventOutcome, InputEvent};

use super::browser::Browser;
use super::cards;
use crate::browser::event::{on_event, on_pages, tab_key};
use crate::browser::tab_groups::inherit;

impl Browser {
    /* One input event to whatever takes it: the tab keys, a page the
     * window draws itself, then the tab in view. */
    pub(super) fn route(&mut self, event: InputEvent) -> EventOutcome {
        self.shell.cards = cards::cards(&self.tabs);
        if let Some(out) = tab_key(&mut self.tabs, &event, inherit(&self.shell)) {
            return self.shown_tab(out);
        }
        if let Some(out) = on_pages(&mut self.tabs, &mut self.shell, &event) {
            return out;
        }
        on_event(self.tabs.active_mut(), &mut self.shell, event)
    }
}
