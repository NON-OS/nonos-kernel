// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

extern crate alloc;

use crate::apps::ecosystem::browser::engine::RenderOutput;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use spin::Mutex;

pub static PAGE_CONTENT: Mutex<Vec<String>> = Mutex::new(Vec::new());
pub static PAGE_RENDER: Mutex<Option<RenderOutput>> = Mutex::new(None);
pub static PAGE_SCROLL: AtomicUsize = AtomicUsize::new(0);
pub static PAGE_TITLE: Mutex<[u8; 128]> = Mutex::new([0u8; 128]);
pub static PAGE_TITLE_LEN: AtomicUsize = AtomicUsize::new(0);
pub static CONTENT_CHANGED: AtomicBool = AtomicBool::new(false);
pub static PAGE_TOTAL_LINES: AtomicUsize = AtomicUsize::new(0);

pub fn mark_content_changed() {
    CONTENT_CHANGED.store(true, Ordering::Relaxed);
}
pub fn take_content_changed() -> bool {
    CONTENT_CHANGED.swap(false, Ordering::Relaxed)
}

pub fn set_page_title(title: &str) {
    let mut buf = PAGE_TITLE.lock();
    let len = title.len().min(127);
    buf[..len].copy_from_slice(&title.as_bytes()[..len]);
    PAGE_TITLE_LEN.store(len, Ordering::Relaxed);
}

pub fn get_page_title() -> Option<String> {
    let len = PAGE_TITLE_LEN.load(Ordering::Relaxed);
    if len > 0 {
        let buf = PAGE_TITLE.lock();
        core::str::from_utf8(&buf[..len]).ok().map(String::from)
    } else {
        None
    }
}

pub fn scroll_up(lines: usize) {
    let current = PAGE_SCROLL.load(Ordering::Relaxed);
    PAGE_SCROLL.store(current.saturating_sub(lines), Ordering::Relaxed);
}

pub fn scroll_down(lines: usize) {
    let current = PAGE_SCROLL.load(Ordering::Relaxed);
    let total = PAGE_TOTAL_LINES.load(Ordering::Relaxed);
    let new_scroll = (current + lines).min(total.saturating_sub(1));
    PAGE_SCROLL.store(new_scroll, Ordering::Relaxed);
}
