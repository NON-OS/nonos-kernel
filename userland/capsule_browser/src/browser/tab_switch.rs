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

use crate::browser::tab_focus::{blur, show};
use crate::browser::tab_scope::{swap, Scope};
use crate::browser::tabs::Tabs;

impl Tabs {
    pub fn switch(&mut self, i: usize) -> bool {
        let moved = i < self.list.len() && i != self.active;
        if moved {
            blur(self.active_mut());
            let was = self.active;
            self.active = i;
            self.list[was].scope = self.take_globals();
            show(self.active_mut());
        }
        moved
    }

    /* Put the active tab's scope in the globals; what they held comes back. */
    pub(super) fn take_globals(&mut self) -> Scope {
        let mut scope = core::mem::take(&mut self.active_mut().scope);
        swap(&mut scope);
        scope
    }
}
