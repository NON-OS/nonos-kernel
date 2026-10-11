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

use crate::browser::tab_focus::{release, show};
use crate::browser::tabs::Tabs;

impl Tabs {
    /// Close tab `i`. The last tab is never closed; it is reset to a blank page.
    pub fn close(&mut self, i: usize) -> bool {
        if i >= self.list.len() {
            return false;
        }
        let was_active = i == self.active;
        let gone = match self.list.len() {
            1 => {
                let blank = self.fresh();
                core::mem::replace(&mut self.list[0], blank)
            }
            _ => self.list.remove(i),
        };
        if i < self.active || self.active >= self.list.len() {
            self.active = self.active.saturating_sub(1);
        }
        if was_active {
            drop(self.take_globals());
            show(self.active_mut());
        }
        release(gone);
        true
    }
}
