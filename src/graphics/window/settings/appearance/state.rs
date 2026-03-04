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

use core::sync::atomic::{AtomicU8, AtomicBool, Ordering};

pub const PREVIEW_WIDTH: u32 = 80;
pub const PREVIEW_HEIGHT: u32 = 50;

static CURRENT_CATEGORY: AtomicU8 = AtomicU8::new(3); // Default to Special Variants
static LAST_RENDERED_CATEGORY: AtomicU8 = AtomicU8::new(0xFF); // Invalid - force first render
static CONTENT_DIRTY: AtomicBool = AtomicBool::new(true);

pub fn get_category() -> u8 {
    CURRENT_CATEGORY.load(Ordering::Relaxed)
}

pub fn get_last_category() -> u8 {
    LAST_RENDERED_CATEGORY.load(Ordering::Relaxed)
}

pub fn set_last_category(cat: u8) {
    LAST_RENDERED_CATEGORY.store(cat, Ordering::Relaxed);
}

pub fn set_category(cat: u8) {
    let old = CURRENT_CATEGORY.swap(cat, Ordering::Relaxed);
    if old != cat {
        mark_content_dirty();
        crate::graphics::window::settings::state::mark_dirty(
            crate::graphics::window::settings::state::PAGE_APPEARANCE
        );
    }
}

pub fn is_content_dirty() -> bool {
    CONTENT_DIRTY.load(Ordering::Relaxed)
}

pub fn mark_content_dirty() {
    CONTENT_DIRTY.store(true, Ordering::Relaxed);
}

pub fn clear_content_dirty() {
    CONTENT_DIRTY.store(false, Ordering::Relaxed);
}

pub fn reset_state() {
    LAST_RENDERED_CATEGORY.store(0xFF, Ordering::Relaxed);
    CONTENT_DIRTY.store(true, Ordering::Relaxed);
}
