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
use crate::browser::paint::{page_parts, pages, reader, sidebar, start, toolbar};
use crate::browser::shell::listing::is_list;
use crate::browser::shell::{Page, Shell};
use crate::browser::state::State;

use super::region::region;

/* Draw what `parts` says changed. A full paint draws the chrome, the
 * sidebar, the view and the settings panel over it; otherwise each dirtied
 * part redraws on its own: the pill for a keystroke, the toolbar for a load
 * starting or ending, the page, a scroll, or just the hovered-link bubble.
 * A page the window draws itself has no parts of its own and is drawn
 * whole. The toolbar
 * and the page each draw into their own rect of the layout; the sidebar and
 * the settings panel draw in window coordinates. */
pub fn paint(state: &mut State, shell: &Shell, fb: &mut PaintBuffer, parts: Damage) {
    let lay = state.layout;
    if parts.has(Damage::FULL) {
        toolbar::paint(state, shell, &mut region(fb, lay.toolbar));
        sidebar::paint(shell, sidebar::current(state, shell), &lay, fb);
        let mut page = region(fb, lay.content);
        match state.on_own {
            true => own(state, shell, &mut page),
            false => {
                page_parts::page_full(state, &mut page);
                super::short_notice::paint(state, &mut page);
            }
        }
        crate::browser::settings::paint(state, fb);
        return;
    }
    if parts.has(Damage::TOOLBAR) {
        toolbar::paint(state, shell, &mut region(fb, lay.toolbar));
    } else if parts.has(Damage::PILL) {
        toolbar::pill(state, &mut region(fb, lay.toolbar));
    }
    let mut page = region(fb, lay.content);
    match state.on_own {
        true if parts.has(Damage::PAGE) => own(state, shell, &mut page),
        true => {}
        false => {
            page_parts::page_parts(state, &mut page, parts);
            super::short_notice::paint(state, &mut page);
        }
    }
}

/* A page the window draws itself, into the content area. */
fn own(state: &State, shell: &Shell, page: &mut PaintBuffer) {
    match shell.page {
        Page::Reader => reader::paint(shell, page),
        p if is_list(p) => pages::paint(shell, page),
        _ => start::paint(state, shell, page),
    }
}
