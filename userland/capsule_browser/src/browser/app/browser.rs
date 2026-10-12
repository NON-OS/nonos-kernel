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

use alloc::string::String;

use crate::browser::paint::tokens;
use crate::browser::shell::kept::Appearance;
use crate::browser::shell::search::template;
use crate::browser::shell::store::load;
use crate::browser::shell::Shell;
use crate::browser::tabs::Tabs;

/* `tabs` are the pages; `shell` the window around them. `cursor` is the
 * next tab out of view to step; `acc` and `strip` the titlebar strip's
 * size and contents at its last paint (`strip::strip_print`). */
pub struct Browser {
    pub(super) tabs: Tabs,
    pub(super) shell: Shell,
    pub(super) cursor: usize,
    pub(super) acc: (i32, i32),
    pub(super) strip: u64,
}

impl Browser {
    /* The bookmarks, appearance and search an earlier run kept are read once,
     * here, before the window opens (`store::load` bounds the wait). */
    pub fn new() -> Self {
        let mut shell = Shell::default();
        shell.apply(load());
        tokens::set_dark(shell.appearance == Appearance::Dark);
        let mut tabs = Tabs::new();
        tabs.active_mut().ui.search = String::from(template(shell.search.as_deref()));
        Browser { tabs, shell, cursor: 0, acc: (0, 0), strip: 0 }
    }
}
