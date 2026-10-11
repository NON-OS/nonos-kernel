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

use crate::browser::omnibox::{hover_update, Change};
use crate::browser::state::{State, View};

/* Pointer motion: track the link under the pointer on the page, hit-tested
 * in viewport space. Only a change of link redraws, and then only the
 * status bubble at the bottom of the page. */
pub(super) fn on_pointer(state: &mut State, event: InputEvent) -> EventOutcome {
    let over_page = state.view == View::Page && !state.on_own && !state.settings_open;
    let page = super::local::local(event, state.layout.content).filter(|_| over_page);
    /* Over an open select list, the row under the pointer is highlighted. */
    if let Some(p) = page.filter(|_| state.ui.select.is_some()) {
        if super::select_open::select_hover(state, p.x, p.y) {
            return EventOutcome::Repaint;
        }
    }
    let next = page.and_then(|p| super::link_under::link_under(state, p.x, p.y));
    if !hover_update(&mut state.ui.hover_href, next.as_deref()) {
        return EventOutcome::Idle;
    }
    state.mark(Change::Bubble);
    EventOutcome::Repaint
}
