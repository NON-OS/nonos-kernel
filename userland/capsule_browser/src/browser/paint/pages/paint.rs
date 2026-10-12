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

use crate::browser::paint::pages::{bookmarks, downloads, extent, header, history, tab_grid};
use crate::browser::paint::tokens::palette;
use crate::browser::shell::cards::shown;
use crate::browser::shell::{Page, Shell};
use crate::browser::ui::list_geom::ListGeom;

/// A list page, into a buffer the size of the content area: the list at
/// its scroll, then the header band over it.
pub fn paint(shell: &Shell, fb: &mut PaintBuffer) {
    fb.fill_rect(0, 0, fb.width, fb.height, palette().ground);
    let shown = shown(shell);
    let (w, h, n) = (fb.width as i32, fb.height as i32, shown.len());
    let g = ListGeom::new(w, h, extent::page_scroll(shell, w, h));
    match shell.page {
        Page::Tabs => tab_grid::paint(shell, &shown, &g, fb),
        Page::Bookmarks => bookmarks::paint(shell, &g, fb),
        Page::Downloads => downloads::paint(shell, &g, fb),
        _ => history::paint(shell, &g, fb),
    }
    header::paint(shell, n, &g, fb);
}
