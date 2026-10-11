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

use crate::browser::event::{on_home_click, on_page_click, on_toolbar};
use crate::browser::shell::Shell;
use crate::browser::state::State;

use super::local::local;

pub fn on_button(state: &mut State, shell: &mut Shell, event: InputEvent) -> EventOutcome {
    /* While the settings panel is open it takes every click: its buttons act,
     * and a click anywhere else closes it. */
    if state.settings_open {
        return crate::browser::settings::on_click(state, event.x, event.y);
    }
    let page = local(event, state.layout.content);
    /* An open select list takes a click on the page; one on the toolbar
     * closes it and goes on. */
    if state.ui.select.is_some() {
        if let Some(at) = page.filter(|_| !state.on_own) {
            return super::select_open::select_click(state, at);
        }
        super::select_open::close_select(state);
    }
    if let Some(at) = local(event, state.layout.toolbar) {
        return on_toolbar::on_toolbar(state, shell, at);
    }
    if state.layout.sidebar.contains(event.x, event.y) {
        return super::on_sidebar::on_sidebar(state, shell, event);
    }
    match (page, state.on_start, state.on_own) {
        (Some(at), true, _) => on_home_click::on_home_click(state, shell, at),
        (Some(at), false, false) => on_page_click::on_page_click(state, at),
        _ => EventOutcome::Idle,
    }
}
