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

use super::state::{get_category, set_category, PREVIEW_HEIGHT, PREVIEW_WIDTH};
use crate::graphics::backgrounds::{
    get_wallpapers_by_category, load_current_wallpaper, set_current_wallpaper,
    WallpaperCategory,
};
use crate::graphics::themes::{next_theme, prev_theme};

pub fn handle_click(x: u32, y: u32, w: u32, click_x: i32, click_y: i32) -> bool {
    if handle_theme_click(x, y, w, click_x, click_y) {
        return true;
    }

    let bg_start_y = y + 80;
    let content_y = bg_start_y + 25;

    handle_wallpapers_click(x, content_y, w, click_x, click_y)
}

fn handle_theme_click(x: u32, y: u32, w: u32, click_x: i32, click_y: i32) -> bool {
    let theme_y = y + 35;

    let prev_x = x + 20;
    if click_x >= prev_x as i32
        && click_x < (prev_x + 26) as i32
        && click_y >= theme_y as i32
        && click_y < (theme_y + 26) as i32
    {
        prev_theme();
        return true;
    }

    let next_x = x + w - 46;
    if click_x >= next_x as i32
        && click_x < (next_x + 26) as i32
        && click_y >= theme_y as i32
        && click_y < (theme_y + 26) as i32
    {
        next_theme();
        return true;
    }

    false
}

fn handle_wallpapers_click(x: u32, y: u32, w: u32, click_x: i32, click_y: i32) -> bool {
    let cat_tab_w = (w - 30) / 4;
    let categories = WallpaperCategory::all();

    for (i, _) in categories.iter().enumerate() {
        let tab_x = (x + 15 + (i as u32) * (cat_tab_w + 2)) as i32;

        if click_x >= tab_x
            && click_x < tab_x + cat_tab_w as i32
            && click_y >= y as i32
            && click_y < (y + 24) as i32
        {
            set_category(i as u8);
            return true;
        }
    }

    let current_category = WallpaperCategory::from_u8(get_category());
    let wallpapers = get_wallpapers_by_category(current_category);

    let content_y = y + 35;
    let start_y = content_y + 25;
    let cols = (w - 40) / (PREVIEW_WIDTH + 15);

    for (i, wallpaper) in wallpapers.iter().enumerate() {
        let col = (i as u32) % cols;
        let row = (i as u32) / cols;
        let px = (x + 20 + col * (PREVIEW_WIDTH + 15)) as i32;
        let py = (start_y + row * (PREVIEW_HEIGHT + 30)) as i32;

        if click_x >= px
            && click_x < px + PREVIEW_WIDTH as i32
            && click_y >= py
            && click_y < py + PREVIEW_HEIGHT as i32
        {
            set_current_wallpaper(wallpaper.id as usize);
            let _ = load_current_wallpaper();
            return true;
        }
    }

    false
}
