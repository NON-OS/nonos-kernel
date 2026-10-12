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

use crate::browser::shell::settings_ui::proxy_text;
use crate::browser::shell::{Page, Shell};
use crate::browser::state::State;
use crate::browser::ui::settings_rows::Field;

/// Shows the settings page from its top, its fields holding what is in
/// force now.
pub fn open(state: &State, shell: &mut Shell) {
    shell.show(Page::Settings);
    for f in [Field::Proxy, Field::Search] {
        let now = current(state, shell, f);
        shell.settings.refill(f, &now);
    }
}

/// What field `f` holds when nothing is being typed in it: the proxy in
/// use, or the custom search template.
pub(super) fn current(state: &State, shell: &Shell, f: Field) -> String {
    match f {
        Field::Proxy => state.proxy.as_ref().map_or(String::new(), |p| proxy_text(&p.host, p.port)),
        Field::Search => shell.search.clone().unwrap_or_default(),
    }
}
