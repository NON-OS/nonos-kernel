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

use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

pub(super) static SELECTED: AtomicUsize = AtomicUsize::new(0);
pub(super) static SCROLL: AtomicUsize = AtomicUsize::new(0);
pub(super) static CATEGORY: AtomicU8 = AtomicU8::new(0);
pub(super) static INSTALLED: [AtomicU8; 32] = [const { AtomicU8::new(0) }; 32];

pub(super) const CAT_ALL: u8 = 0;
pub(super) const CAT_SOCIAL: u8 = 1;
pub(super) const CAT_BROWSER: u8 = 2;
pub(super) const CAT_TOOLS: u8 = 3;

pub(super) fn selected() -> usize {
    SELECTED.load(Ordering::Relaxed)
}
pub(super) fn scroll() -> usize {
    SCROLL.load(Ordering::Relaxed)
}
pub(super) fn category() -> u8 {
    CATEGORY.load(Ordering::Relaxed)
}
pub(super) fn is_installed(idx: usize) -> bool {
    if idx < 32 {
        INSTALLED[idx].load(Ordering::Relaxed) == 1
    } else {
        false
    }
}

pub(super) fn select(idx: usize) {
    SELECTED.store(idx, Ordering::Relaxed);
}
pub(super) fn set_category(c: u8) {
    CATEGORY.store(c, Ordering::Relaxed);
}
pub(super) fn set_installed(idx: usize, v: bool) {
    if idx < 32 {
        INSTALLED[idx].store(if v { 1 } else { 0 }, Ordering::Relaxed);
    }
}
