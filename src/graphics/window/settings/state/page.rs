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

pub const SIDEBAR_WIDTH: u32 = 120;
pub const PAGE_PRIVACY: u8 = 0;
pub const PAGE_NETWORK: u8 = 1;
pub const PAGE_APPEARANCE: u8 = 2;
pub const PAGE_SYSTEM: u8 = 3;
pub const PAGE_POWER: u8 = 4;
pub const PAGE_COUNT: u8 = 5;

static SETTINGS_PAGE: AtomicU8 = AtomicU8::new(0);

pub fn get_page() -> u8 {
    SETTINGS_PAGE.load(Ordering::Relaxed)
}

pub fn set_page(page: u8) {
    if page <= PAGE_POWER {
        SETTINGS_PAGE.store(page, Ordering::Relaxed);
    }
}

pub fn reset_render_state() {
    SETTINGS_PAGE.store(0, Ordering::Relaxed);
}
