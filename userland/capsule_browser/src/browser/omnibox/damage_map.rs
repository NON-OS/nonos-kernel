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

use super::damage::Damage;
use super::geometry::{bubble_band, pill_rect, search_rect, Rect};
use crate::browser::ui::layout::Layout;

/* What changed, in the terms the event and tick code speak. */
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    OmniboxEdit,
    /* On the home page the search bar mirrors the address text. */
    HomeEdit,
    Toolbar,
    Page,
    Scroll,
    Bubble,
    Full,
}

pub fn bits(c: Change) -> Damage {
    match c {
        Change::OmniboxEdit => Damage::PILL,
        Change::HomeEdit => Damage(Damage::PILL.0 | Damage::HOME_BAR.0),
        Change::Toolbar => Damage::TOOLBAR,
        Change::Page => Damage::PAGE,
        Change::Scroll => Damage::SCROLL,
        Change::Bubble => Damage::BUBBLE,
        Change::Full => Damage::FULL,
    }
}

/* The rect covering every dirtied part of the surface `lay` splits, or
 * None when the whole window has to be drawn: a full change, or nothing
 * recorded to go by. */
pub fn rect_of(d: Damage, lay: &Layout) -> Option<Rect> {
    if d.is_empty() || d.has(Damage::FULL) {
        return None;
    }
    let (bar, page) = (Rect::from(lay.toolbar), Rect::from(lay.content));
    let parts = [
        (Damage::PILL, pill_rect(bar.w).within(bar)),
        (Damage::TOOLBAR, bar),
        (Damage::HOME_BAR, search_rect(page.w).within(page)),
        (Damage(Damage::PAGE.0 | Damage::SCROLL.0), page),
        (Damage::BUBBLE, bubble_band(page)),
    ];
    parts.iter().filter(|(b, _)| d.has(*b)).map(|(_, r)| *r).reduce(Rect::union)
}

#[cfg(test)]
pub fn damage_for(c: Change, width: u32, height: u32) -> Option<Rect> {
    use crate::browser::ui::layout::{compute, SidebarMode};
    rect_of(bits(c), &compute(width as i32, height as i32, SidebarMode::Hidden))
}
