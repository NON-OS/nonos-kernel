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

use crate::browser::omnibox::{focus_after, Focus, Region};
use crate::browser::paint::start::{favourites, geom};
use crate::browser::shell::Shell;
use crate::browser::state::{Origin, State};
use crate::browser::ui::start_geom::{fav_at, pill_text};

/* A click on the start page, in content-local coordinates, hit-tested
 * against the geometry it was painted with. The search pill takes the
 * keyboard, or, already holding it, moves the caret to the click; a
 * favourite goes to its site. */
pub fn on_home_click(state: &mut State, shell: &mut Shell, event: InputEvent) -> EventOutcome {
    let favs = favourites(shell);
    let g = geom(shell, favs.len(), state.viewport_w as i32, state.viewport_h as i32);
    let text = pill_text(&g).filter(|_| g.pill.contains(event.x, event.y));
    let region = if text.is_some() { Region::Omnibox } else { Region::Page };
    match (focus_after(region, None, state.ui.kbd), text) {
        ((Focus::Omnibox, _), Some(t)) if state.ui.kbd == Focus::Omnibox => {
            let origin = t.x - state.start_text_off(t.w);
            super::pill_caret::caret_to(state, event.x - origin);
        }
        ((Focus::Omnibox, _), _) if state.ui.kbd == Focus::Omnibox => {}
        ((Focus::Omnibox, _), _) => {
            state.focus_omnibox();
            state.fit_text();
        }
        ((Focus::Page, field), _) => state.focus_page(field),
    }
    match fav_at(&g, event.x, event.y).and_then(|i| favs.get(i)) {
        Some(f) => super::navigate::navigate(state, f.url.clone(), Origin::User),
        None => EventOutcome::Idle,
    }
}
