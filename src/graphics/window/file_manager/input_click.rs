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

use super::constants::*;
use super::input_content::handle_content_click;
use super::input_sidebar::handle_sidebar_click;

pub fn handle_click(win_x: u32, win_y: u32, win_w: u32, click_x: i32, click_y: i32) -> bool {
    let content_y = win_y as i32;
    let sidebar_w = SIDEBAR_WIDTH as i32;

    if click_x >= win_x as i32 && click_x < win_x as i32 + sidebar_w {
        return handle_sidebar_click(win_x, content_y, click_x, click_y);
    }

    handle_content_click(win_x, win_w, content_y, click_x, click_y)
}
