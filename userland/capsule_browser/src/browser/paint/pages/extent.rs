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

use crate::browser::paint::reader;
use crate::browser::paint::start::favourites;
use crate::browser::shell::cards::shown;
use crate::browser::shell::listing::{is_list, row_count};
use crate::browser::shell::{Page, Shell};
use crate::browser::ui::list_geom::{max_scroll, ListGeom};
use crate::browser::ui::settings_geom::SettingsGeom;
use crate::browser::ui::start_geom;

/// The scroll the page the window draws itself is drawn at:
/// `shell.page_scroll` held to how far that page, in a `w` x `h` view, can
/// go. Painters, the wheel, the keys and clicks all read it here.
pub fn page_scroll(shell: &Shell, w: i32, h: i32) -> i32 {
    let g = ListGeom::new(w, h, 0);
    let content = match shell.page {
        Page::Tabs => g.grid_h(shown(shell).len(), g.cols()),
        Page::Reader => reader::height(shell, w),
        Page::Settings => SettingsGeom::new(w, h, 0).height,
        p if is_list(p) => g.list_h(row_count(shell).max(1)),
        _ => {
            let favs = favourites(shell).len();
            return -start_geom::scrolled(w, h, favs, shell.page_scroll).hero.y;
        }
    };
    shell.page_scroll.clamp(0, max_scroll(content, h))
}
