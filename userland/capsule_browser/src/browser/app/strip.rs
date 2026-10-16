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

use crate::browser::paint::tabbar::label;
use crate::browser::paint::tokens;
use crate::browser::tabs::Tabs;

use super::print::fold;

/* What the titlebar's tab strip shows: how many tabs, which is in view,
 * each one's label, glyph and busy dot, and the appearance it is drawn
 * under. The frame around the content is drawn only on a whole-window
 * repaint, so a change here asks for one. */
pub(super) fn strip_print(tabs: &Tabs) -> u64 {
    let mut h = fold(fold(0xcbf2_9ce4_8422_2325, tabs.list.len() as u64), tabs.active as u64);
    h = fold(h, tokens::key());
    for s in tabs.list.iter() {
        h = fold(fold(h, s.loading() as u64), s.view as u64);
        h = label(s).bytes().fold(h, |h, b| fold(h, b as u64));
    }
    h
}
