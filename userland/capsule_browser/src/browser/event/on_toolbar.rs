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

use crate::browser::event::{nav_history, navigate};
use crate::browser::omnibox::{focus_after, toolbar_button_at, Btn, Change, Focus, Region};
use crate::browser::state::State;

/* A click on the toolbar, hit-tested at the width the toolbar was drawn. A
 * button acts without taking the caret; the pill takes the keyboard and
 * selects its text, or, already focused, moves the caret to the click. */
pub fn on_toolbar(state: &mut State, event: InputEvent) -> EventOutcome {
    let btn = toolbar_button_at(event.x, event.y, state.layout.toolbar.w as u32);
    let region = match btn {
        Some(Btn::Url) => Region::Omnibox,
        Some(_) => Region::Toolbar,
        None => Region::Frame,
    };
    let (kbd, field) = focus_after(region, state.focus, state.ui.kbd);
    match (kbd, state.ui.kbd, btn) {
        (Focus::Omnibox, Focus::Omnibox, Some(Btn::Url)) => {
            super::pill_caret::place_caret(state, event.x);
            return EventOutcome::Repaint;
        }
        (Focus::Omnibox, Focus::Omnibox, _) => {}
        (Focus::Omnibox, _, _) => {
            state.focus_omnibox();
            state.fit_text();
        }
        (Focus::Page, _, _) => state.focus_page(field),
    }
    match btn {
        Some(Btn::Home) => navigate::go_home(state),
        Some(Btn::Reload) if state.loading() => {
            super::stop::stop(state);
            EventOutcome::Repaint
        }
        Some(Btn::Reload) => navigate::reload(state),
        Some(Btn::Back) => nav_history::nav_history(state, -1),
        Some(Btn::Forward) => nav_history::nav_history(state, 1),
        Some(Btn::Menu) => {
            state.settings_open = !state.settings_open;
            state.mark(Change::Full);
            EventOutcome::Repaint
        }
        Some(Btn::Url) | None => EventOutcome::Idle,
    }
}
