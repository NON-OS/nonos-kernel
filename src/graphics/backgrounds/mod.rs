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

pub mod images;
pub mod wallpaper_data;
pub mod state;
pub mod wallpaper;

pub use images::Background as BackgroundType;
pub(crate) use images::{BG_HEIGHT, BG_WIDTH};
pub(crate) use state::{get_background, next_background, prev_background};
pub use state::{get_background_pixels, has_wallpaper_image, get_wallpaper_image};
pub use wallpaper::{
    get_cached_wallpaper, get_current_wallpaper_id, get_wallpaper, get_wallpapers_by_category,
    is_using_wallpaper, load_current_wallpaper, next_wallpaper, prev_wallpaper,
    set_current_wallpaper, WallpaperCategory, WallpaperInfo, WALLPAPERS, WALLPAPER_COUNT,
    init_wallpaper_system, has_embedded_wallpaper, DEFAULT_WALLPAPER_ID,
};
