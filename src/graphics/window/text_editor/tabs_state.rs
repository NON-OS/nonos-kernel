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

use super::syntax::Language;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

pub const MAX_TABS: usize = 8;
pub const TAB_BUFFER_SIZE: usize = 16384;
pub const TAB_PATH_SIZE: usize = 256;

pub struct TabBuffer {
    pub data: [u8; TAB_BUFFER_SIZE],
    pub len: usize,
    pub cursor: usize,
    pub scroll_y: usize,
    pub path: [u8; TAB_PATH_SIZE],
    pub path_len: usize,
    pub modified: bool,
    pub language: Language,
    pub active: bool,
}

impl TabBuffer {
    pub const fn new() -> Self {
        Self {
            data: [0; TAB_BUFFER_SIZE],
            len: 0,
            cursor: 0,
            scroll_y: 0,
            path: [0; TAB_PATH_SIZE],
            path_len: 0,
            modified: false,
            language: Language::Plain,
            active: false,
        }
    }
}

pub(super) static mut TABS: [TabBuffer; MAX_TABS] = [
    TabBuffer::new(),
    TabBuffer::new(),
    TabBuffer::new(),
    TabBuffer::new(),
    TabBuffer::new(),
    TabBuffer::new(),
    TabBuffer::new(),
    TabBuffer::new(),
];
pub(super) static ACTIVE_TAB: AtomicUsize = AtomicUsize::new(0);
pub(super) static TAB_COUNT: AtomicUsize = AtomicUsize::new(1);
static TABS_ENABLED: AtomicBool = AtomicBool::new(false);

pub fn enable_tabs() {
    TABS_ENABLED.store(true, Ordering::Relaxed);
    unsafe {
        TABS[0].active = true;
    }
}
pub fn tabs_enabled() -> bool {
    TABS_ENABLED.load(Ordering::Relaxed)
}
pub fn active_tab() -> usize {
    ACTIVE_TAB.load(Ordering::Relaxed)
}
pub fn tab_count() -> usize {
    TAB_COUNT.load(Ordering::Relaxed)
}

pub use super::tabs_ops::{close_tab, get_tab_name, is_tab_modified, new_tab, switch_tab};
