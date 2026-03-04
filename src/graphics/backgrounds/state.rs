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

use core::sync::atomic::{AtomicU8, Ordering};
use super::images::Background;
use super::wallpaper::{
    is_using_wallpaper, get_cached_wallpaper, next_wallpaper, prev_wallpaper, set_current_wallpaper,
};

static CURRENT_BACKGROUND: AtomicU8 = AtomicU8::new(1);

pub(crate) fn get_background() -> Background {
    Background::from_u8(CURRENT_BACKGROUND.load(Ordering::Relaxed))
}

pub(crate) fn set_background(bg: Background) {
    CURRENT_BACKGROUND.store(bg as u8, Ordering::Relaxed);
    set_current_wallpaper(255);
}

pub(crate) fn next_background() -> Background {
    if is_using_wallpaper() {
        next_wallpaper();
        return get_background();
    }

    let current = get_background();
    let next = current.next();
    set_background(next);
    next
}

pub(crate) fn prev_background() -> Background {
    if is_using_wallpaper() {
        prev_wallpaper();
        return get_background();
    }

    let current = get_background();
    let prev = current.prev();
    set_background(prev);
    prev
}

pub fn get_background_pixels() -> Option<&'static [u32]> {
    if is_using_wallpaper() {
        if let Some(img) = get_cached_wallpaper() {
            return Some(img.pixels.as_slice());
        }
    }

    get_background().pixels()
}

pub fn has_wallpaper_image() -> bool {
    is_using_wallpaper() && get_cached_wallpaper().is_some()
}

pub fn get_wallpaper_image() -> Option<&'static crate::graphics::image::DecodedImage> {
    if is_using_wallpaper() {
        get_cached_wallpaper()
    } else {
        None
    }
}
