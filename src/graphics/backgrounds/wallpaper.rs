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

extern crate alloc;

use alloc::vec::Vec;
use core::ptr::{addr_of, addr_of_mut};
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::graphics::image::{decode_png, DecodedImage};

use super::wallpaper_data::get_embedded_wallpaper_data;

pub use super::wallpaper_data::{
    WallpaperCategory, WallpaperInfo, WALLPAPERS, WALLPAPER_COUNT, DEFAULT_WALLPAPER_ID,
    category_count,
};

static CURRENT_WALLPAPER: AtomicUsize = AtomicUsize::new(DEFAULT_WALLPAPER_ID as usize);
static mut CACHED_WALLPAPER: Option<DecodedImage> = None;
static CACHED_WALLPAPER_ID: AtomicUsize = AtomicUsize::new(usize::MAX);

pub fn get_wallpapers_by_category(category: WallpaperCategory) -> Vec<&'static WallpaperInfo> {
    WALLPAPERS.iter().filter(|w| w.category == category).collect()
}

pub fn get_wallpaper(id: u8) -> Option<&'static WallpaperInfo> {
    WALLPAPERS.iter().find(|w| w.id == id)
}

pub fn get_current_wallpaper_id() -> usize {
    CURRENT_WALLPAPER.load(Ordering::Relaxed)
}

pub fn set_current_wallpaper(id: usize) {
    CURRENT_WALLPAPER.store(id, Ordering::Relaxed);
    if CACHED_WALLPAPER_ID.load(Ordering::Relaxed) != id {
        // SAFETY: Single-threaded access during wallpaper change
        unsafe { *addr_of_mut!(CACHED_WALLPAPER) = None; }
        CACHED_WALLPAPER_ID.store(usize::MAX, Ordering::Relaxed);
    }
}

pub fn is_using_wallpaper() -> bool {
    get_current_wallpaper_id() < WALLPAPER_COUNT
}

pub fn load_current_wallpaper() -> Option<&'static DecodedImage> {
    let id = get_current_wallpaper_id();

    if id >= WALLPAPER_COUNT {
        return None;
    }

    if CACHED_WALLPAPER_ID.load(Ordering::Relaxed) == id {
        // SAFETY: Cache is only modified during load, single-threaded
        unsafe { return (*addr_of!(CACHED_WALLPAPER)).as_ref(); }
    }

    let png_data = get_embedded_wallpaper_data(id as u8)?;
    let image = decode_png(png_data)?;

    // SAFETY: Single-threaded cache update
    unsafe {
        *addr_of_mut!(CACHED_WALLPAPER) = Some(image);
        CACHED_WALLPAPER_ID.store(id, Ordering::Relaxed);
        (*addr_of!(CACHED_WALLPAPER)).as_ref()
    }
}

pub fn get_cached_wallpaper() -> Option<&'static DecodedImage> {
    let id = get_current_wallpaper_id();
    if CACHED_WALLPAPER_ID.load(Ordering::Relaxed) == id {
        // SAFETY: Cache read is safe after store
        unsafe { (*addr_of!(CACHED_WALLPAPER)).as_ref() }
    } else {
        None
    }
}

pub fn next_wallpaper() -> usize {
    let current = get_current_wallpaper_id();
    let next = if current >= WALLPAPER_COUNT {
        0
    } else if current + 1 >= WALLPAPER_COUNT {
        0
    } else {
        current + 1
    };
    set_current_wallpaper(next);
    next
}

pub fn prev_wallpaper() -> usize {
    let current = get_current_wallpaper_id();
    let prev = if current == 0 {
        WALLPAPER_COUNT - 1
    } else if current >= WALLPAPER_COUNT {
        WALLPAPER_COUNT - 1
    } else {
        current - 1
    };
    set_current_wallpaper(prev);
    prev
}

pub fn init_wallpaper_system() {
    if load_current_wallpaper().is_none() {
        set_current_wallpaper(0);
        let _ = load_current_wallpaper();
    }
}

pub fn has_embedded_wallpaper() -> bool {
    true
}
