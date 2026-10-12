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

use crate::browser::shell::search::{check, template};
use crate::browser::shell::{store, Shell};
use crate::browser::tabs::Tabs;
use crate::browser::ui::settings_rows::Field;

/// The Engine row: DuckDuckGo searches the default engine again; Custom
/// takes the template in its field, or hands that field the keyboard
/// while it is empty.
pub(super) fn pick(tabs: &mut Tabs, shell: &mut Shell, i: u8) {
    if i == 0 {
        shell.settings.search_err = None;
        return use_template(tabs, shell, None);
    }
    match shell.settings.search.text.trim().is_empty() {
        true => shell.settings.focus = Some(Field::Search),
        false => apply(tabs, shell),
    }
}

/// Takes the template typed in the search field, or says under it why not.
pub(super) fn apply(tabs: &mut Tabs, shell: &mut Shell) {
    match check(&shell.settings.search.text) {
        Ok(t) => {
            shell.settings.refill(Field::Search, &t);
            use_template(tabs, shell, Some(t));
        }
        Err(why) => {
            shell.settings.search_err = Some(why);
            shell.settings.focus = Some(Field::Search);
        }
    }
}

/* Every tab searches with `custom`, or the default engine; a tab opened
 * later takes it from the one it opens beside. Saved with the bookmarks. */
fn use_template(tabs: &mut Tabs, shell: &mut Shell, custom: Option<String>) {
    let t = String::from(template(custom.as_deref()));
    for s in tabs.list.iter_mut() {
        s.ui.search.clone_from(&t);
    }
    shell.search = custom;
    store::sync(shell);
}
