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

use super::geometry::{pill_rect, BACK_X, BTN_W, FWD_X, HOME_X, MENU_W, RELOAD_X};
use crate::browser::ui::limits::TOOLBAR_H;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Btn {
    Back,
    Forward,
    Reload,
    Home,
    Url,
    Menu,
}

/* The toolbar control under (x, y) for a toolbar `width` pixels wide. The
 * menu and the pill's right end follow the real width, as they are drawn. */
pub fn toolbar_button_at(x: i32, y: i32, width: u32) -> Option<Btn> {
    if !(0..TOOLBAR_H).contains(&y) || x < 0 {
        return None;
    }
    let hit = |base: i32| x >= base && x < base + BTN_W;
    let buttons =
        [(BACK_X, Btn::Back), (FWD_X, Btn::Forward), (RELOAD_X, Btn::Reload), (HOME_X, Btn::Home)];
    if let Some((_, b)) = buttons.iter().find(|(bx, _)| hit(*bx)) {
        return Some(*b);
    }
    let w = width as i32;
    if x >= w - MENU_W && x < w {
        return Some(Btn::Menu);
    }
    let p = pill_rect(width);
    if x >= p.x as i32 && x < (p.x + p.w) as i32 {
        return Some(Btn::Url);
    }
    None
}
