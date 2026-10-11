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

use crate::browser::shell::site_label;
use crate::browser::state::State;

/// What a tab is called: its page's title, the site when the title is
/// blank, and "New Tab" before it has loaded anything.
pub fn label(st: &State) -> String {
    match site_label::title(&st.title, &st.ui.current_url) {
        t if t.is_empty() => String::from("New Tab"),
        t => t,
    }
}
