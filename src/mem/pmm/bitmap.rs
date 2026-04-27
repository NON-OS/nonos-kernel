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

use super::state::{BITMAP_SIZE, PAGE_BITMAP};
use core::sync::atomic::Ordering;

pub(super) fn mark_page_allocated(page: usize) {
    let word_idx = page / 64;
    let bit_idx = page % 64;
    if word_idx < BITMAP_SIZE {
        unsafe {
            PAGE_BITMAP[word_idx].fetch_or(1u64 << bit_idx, Ordering::SeqCst);
        }
    }
}

pub(super) fn mark_page_free(page: usize) {
    let word_idx = page / 64;
    let bit_idx = page % 64;
    if word_idx < BITMAP_SIZE {
        unsafe {
            PAGE_BITMAP[word_idx].fetch_and(!(1u64 << bit_idx), Ordering::SeqCst);
        }
    }
}

pub(super) fn is_page_allocated(page: usize) -> bool {
    let word_idx = page / 64;
    let bit_idx = page % 64;
    if word_idx < BITMAP_SIZE {
        unsafe { PAGE_BITMAP[word_idx].load(Ordering::Relaxed) & (1u64 << bit_idx) != 0 }
    } else {
        true
    }
}

pub(super) fn get_bitmap_word(word_idx: usize) -> u64 {
    if word_idx < BITMAP_SIZE {
        unsafe { PAGE_BITMAP[word_idx].load(Ordering::Relaxed) }
    } else {
        0xFFFF_FFFF_FFFF_FFFF
    }
}
