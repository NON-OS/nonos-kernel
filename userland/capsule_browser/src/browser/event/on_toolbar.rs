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
use crate::browser::omnibox::{focus_after, Change, Focus, Region};
use crate::browser::shell::{Page, Shell};
use crate::browser::state::{State, View};
use crate::browser::tab_groups;
use crate::browser::ui::rect::Rect;
use crate::browser::ui::toolbar_geom::{buttons, hit, Part};

/* A click on the toolbar, hit-tested against the geometry it was drawn
 * with. A button acts without taking the caret; the pill takes the keyboard
 * and selects its text, or, already focused, moves the caret to the click.
 * The route badge opens the settings panel, which the sidebar's Settings
 * row also reaches; with the sidebar hidden the badge is the way in, as
 * Reader and Tabs are to the reader and the Tabs page. Back from a page
 * the window draws over a loaded tab returns to that tab's page. */
pub fn on_toolbar(state: &mut State, shell: &mut Shell, event: InputEvent) -> EventOutcome {
    let bar = state.layout.toolbar;
    let btn = hit(&buttons(Rect::new(0, 0, bar.w, bar.h)), event.x, event.y);
    let region = match btn {
        Some(Part::Pill) => Region::Omnibox,
        Some(_) => Region::Toolbar,
        None => Region::Frame,
    };
    let (kbd, field) = focus_after(region, state.focus, state.ui.kbd);
    match (kbd, state.ui.kbd, btn) {
        (Focus::Omnibox, Focus::Omnibox, Some(Part::Pill)) => {
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
        Some(Part::Home) => {
            shell.show(Page::Web);
            navigate::go_home(state)
        }
        Some(Part::Reload) if state.loading() => {
            super::stop::stop(state);
            EventOutcome::Repaint
        }
        Some(Part::Reload) => navigate::reload(state),
        Some(Part::Back) if shell.page != Page::Web && state.view == View::Page => {
            super::window_buttons::leave_start(state, shell)
        }
        Some(Part::Back) => nav_history::nav_history(state, -1),
        Some(Part::Fwd) => nav_history::nav_history(state, 1),
        Some(Part::Star) => super::window_buttons::toggle_star(state, shell),
        Some(Part::Reader) => super::reader_toggle::toggle(state, shell),
        Some(Part::Tabs) => {
            tab_groups::show(shell, None);
            EventOutcome::Repaint
        }
        Some(Part::Sidebar) => super::window_buttons::cycle_sidebar(state, shell),
        Some(Part::Route) => {
            state.settings_open = !state.settings_open;
            state.mark(Change::Full);
            EventOutcome::Repaint
        }
        Some(Part::Pill) | None => EventOutcome::Idle,
    }
}
