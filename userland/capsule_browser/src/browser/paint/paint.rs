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

use nonos_app_skeleton::PaintBuffer;

use crate::browser::omnibox::Damage;
use crate::browser::paint::{home_page, page_parts, toolbar};
use crate::browser::state::{State, View};

use super::region::region;

/* Draw what `parts` says changed. A full paint draws the chrome, the view
 * and the settings panel over it; otherwise each dirtied part redraws on
 * its own: the pill for a keystroke, the toolbar for a load starting or
 * ending, the page, a scroll, or just the hovered-link bubble. The toolbar
 * and the page each draw into their own rect of the layout; the settings
 * panel draws over the whole surface. */
pub fn paint(state: &mut State, fb: &mut PaintBuffer, parts: Damage) {
    let lay = state.layout;
    if parts.has(Damage::FULL) {
        toolbar::paint(state, &mut region(fb, lay.toolbar));
        let mut page = region(fb, lay.content);
        match state.view {
            View::Home => home_page::paint(state, &mut page),
            View::Page => page_parts::page_full(state, &mut page),
        }
        super::short_notice::paint(state, &mut page);
        crate::browser::settings::paint(state, fb);
        return;
    }
    if parts.has(Damage::TOOLBAR) {
        toolbar::paint(state, &mut region(fb, lay.toolbar));
    } else if parts.has(Damage::PILL) {
        toolbar::pill(state, &mut region(fb, lay.toolbar));
    }
    let mut page = region(fb, lay.content);
    match state.view {
        View::Home if parts.has(Damage::PAGE) => home_page::paint(state, &mut page),
        View::Home if parts.has(Damage::HOME_BAR) => home_page::search_bar(state, &mut page),
        View::Home => {}
        View::Page => {
            page_parts::page_parts(state, &mut page, parts);
            super::short_notice::paint(state, &mut page);
        }
    }
}
