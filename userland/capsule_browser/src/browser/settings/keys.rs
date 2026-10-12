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

use nonos_app_skeleton::{EventOutcome, InputEvent, InputKind};

use crate::browser::event::line_keys::edit;
use crate::browser::omnibox::{edit_key, Change, EditKey};
use crate::browser::shell::{Page, Shell};
use crate::browser::tabs::Tabs;
use crate::browser::ui::settings_geom::Field;

/// A key while a settings field has the keyboard: Enter applies the field,
/// Esc puts back what is in force and lets go, Ctrl+L and its kin hand the
/// keyboard to the address bar, and the rest edit the field. None when no
/// field has the keyboard, so the key takes the usual path.
pub fn key(tabs: &mut Tabs, shell: &mut Shell, event: &InputEvent) -> Option<EventOutcome> {
    if event.kind != InputKind::KeyDown || shell.page != Page::Settings {
        return None;
    }
    let f = shell.settings.focus?;
    match edit_key(event.code, event.flags) {
        EditKey::FocusOmnibox => {
            shell.settings.focus = None;
            return None;
        }
        EditKey::Commit => commit(tabs, shell, f),
        EditKey::Cancel => {
            let now = super::open::current(tabs.active(), shell, f);
            shell.settings.refill(f, &now);
            shell.settings.focus = None;
        }
        EditKey::Ignore => return Some(EventOutcome::Idle),
        k => return Some(typed(tabs, shell, f, k)),
    }
    tabs.active_mut().mark(Change::Full);
    Some(EventOutcome::Repaint)
}

/* Enter: the field's own button. The field lets go of the keyboard once
 * what it holds is taken. */
fn commit(tabs: &mut Tabs, shell: &mut Shell, f: Field) {
    match f {
        Field::Proxy => super::net_act::set_proxy(tabs, shell),
        Field::Search => super::search_act::apply(tabs, shell),
    }
    if shell.settings.refusal(f).is_none() {
        shell.settings.focus = None;
    }
}

fn typed(tabs: &mut Tabs, shell: &mut Shell, f: Field, k: EditKey) -> EventOutcome {
    match edit(shell.settings.field(f), k) {
        Ok(true) => {
            *shell.settings.refusal(f) = None;
            tabs.active_mut().mark(Change::Page);
            EventOutcome::Repaint
        }
        Ok(false) => EventOutcome::Idle,
        Err(e) => {
            tabs.active_mut().tell(String::from(e));
            EventOutcome::Idle
        }
    }
}
