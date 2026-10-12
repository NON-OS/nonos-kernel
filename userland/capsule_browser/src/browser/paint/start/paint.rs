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

use crate::browser::paint::start::{cards, favorites, favourites, hero};
use crate::browser::paint::tokens::palette;
use crate::browser::shell::Shell;
use crate::browser::state::State;
use crate::browser::ui::start_geom::{self, StartGeom};

/// The start page's geometry in a `w` x `h` content area, as the painter
/// and the click handler both place it.
pub fn geom(shell: &Shell, favs: usize, w: i32, h: i32) -> StartGeom {
    start_geom::scrolled(w, h, favs, shell.page_scroll)
}

/// The start page, into a buffer the size of the content area: the sky
/// band with the greeting and search pill, the favourites, then the cards.
pub fn paint(state: &State, shell: &Shell, fb: &mut PaintBuffer) {
    fb.fill_rect(0, 0, fb.width, fb.height, palette().ground);
    let favs = favourites(shell);
    let g = geom(shell, favs.len(), fb.width as i32, fb.height as i32);
    hero::paint(state, &g, fb);
    favorites::paint(&g, &favs, fb);
    cards::paint(state, shell, &g, fb);
}
