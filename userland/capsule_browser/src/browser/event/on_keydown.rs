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

use crate::browser::omnibox::{edit_key, route, EditKey, Route};
use crate::browser::state::State;

/* A key goes to the address bar or to the page, whichever holds the
 * keyboard. Ctrl+L, Alt+D and F6 reach the address bar from anywhere. */
pub(super) fn on_keydown(state: &mut State, event: InputEvent) -> EventOutcome {
    if state.settings_open {
        return EventOutcome::Idle;
    }
    if edit_key(event.code, event.flags) == EditKey::FocusOmnibox {
        super::select_open::close_select(state);
        state.focus_omnibox();
        state.fit_text();
        return EventOutcome::Repaint;
    }
    /* An open select list has the keyboard until it closes. */
    if state.ui.select.is_some() {
        return super::select_open::select_key(state, event);
    }
    match route(state.ui.kbd, state.focus, event.code) {
        Route::Omnibox => super::on_key::on_key(state, event),
        _ if state.on_start => EventOutcome::Idle,
        /* The page hears the key first, and keeps it when a listener
         * cancels it: no typing, scrolling, Tab or submit then. */
        _ if super::page_input::page_keydown(state, event) => EventOutcome::Idle,
        r => super::on_page_key::on_page_key(state, event, r),
    }
}
