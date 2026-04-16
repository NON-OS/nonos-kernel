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

use core::sync::atomic::Ordering;
use spin::Mutex;
use super::super::{PhysAddr, PAGE_SIZE, PAGE_SHIFT};
use super::state::{TOTAL_PAGES, FREE_PAGES, MAX_BITMAP_PAGES, BITMAP_SIZE};
use super::bitmap::{mark_page_allocated, mark_page_free, is_page_allocated, get_bitmap_word};

static PMM_LOCK: Mutex<()> = Mutex::new(());

pub fn alloc_page() -> Option<PhysAddr> {
    alloc_pages(1)
}

pub fn alloc_pages(count: usize) -> Option<PhysAddr> {
    if count == 0 {
        return None;
    }
    let _guard = PMM_LOCK.lock();

    let total = TOTAL_PAGES.load(Ordering::Relaxed);
    let mut start_page = 0usize;

    'outer: while start_page + count <= total {
        let word_start = start_page / 64;

        for word_idx in word_start..BITMAP_SIZE {
            let word = get_bitmap_word(word_idx);
            if word == 0xFFFF_FFFF_FFFF_FFFF {
                continue;
            }

            for bit in 0..64 {
                let page = word_idx * 64 + bit;
                if page >= total {
                    return None;
                }

                for offset in 0..count {
                    if is_page_allocated(page + offset) {
                        start_page = page + offset + 1;
                        continue 'outer;
                    }
                }

                for offset in 0..count {
                    mark_page_allocated(page + offset);
                }
                FREE_PAGES.fetch_sub(count, Ordering::SeqCst);
                return Some((page as u64) << PAGE_SHIFT);
            }
        }
        break;
    }

    None
}

pub fn alloc_pages_aligned(count: usize, alignment: usize) -> Option<PhysAddr> {
    if count == 0 || alignment < PAGE_SIZE || !alignment.is_power_of_two() {
        return None;
    }
    let _guard = PMM_LOCK.lock();

    let align_pages = alignment / PAGE_SIZE;
    let total = TOTAL_PAGES.load(Ordering::Relaxed);
    let mut page = 0usize;

    while page + count <= total {
        page = (page + align_pages - 1) & !(align_pages - 1);
        if page + count > total {
            break;
        }

        let mut all_free = true;
        for offset in 0..count {
            if is_page_allocated(page + offset) {
                all_free = false;
                page += offset + 1;
                break;
            }
        }

        if all_free {
            for offset in 0..count {
                mark_page_allocated(page + offset);
            }
            FREE_PAGES.fetch_sub(count, Ordering::SeqCst);
            return Some((page as u64) << PAGE_SHIFT);
        }
    }

    None
}

pub fn free_page(addr: PhysAddr) {
    free_pages(addr, 1);
}

pub fn free_pages(addr: PhysAddr, count: usize) {
    if count == 0 {
        return;
    }
    let _guard = PMM_LOCK.lock();

    let start_page = (addr >> PAGE_SHIFT) as usize;

    for offset in 0..count {
        let page = start_page + offset;
        if page < MAX_BITMAP_PAGES && is_page_allocated(page) {
            mark_page_free(page);
            FREE_PAGES.fetch_add(1, Ordering::SeqCst);
        }
    }
}
