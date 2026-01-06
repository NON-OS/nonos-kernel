// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use alloc::collections::BTreeMap;
use core::sync::atomic::Ordering;
use spin::Mutex;
use x86_64::{PhysAddr, VirtAddr};
use crate::memory::layout;
use super::constants::*;
use super::error::{PageInfoError, PageInfoResult};
use super::types::*;
static PAGE_INFO_MANAGER: Mutex<PageInfoManager> = Mutex::new(PageInfoManager::new());
static PAGE_STATS: PageStats = PageStats::new();

struct PageInfoManager {
    pages: BTreeMap<u64, PageInfo>,
    initialized: bool,
}

impl PageInfoManager {
    const fn new() -> Self {
        Self { pages: BTreeMap::new(), initialized: false }
    }

    fn init(&mut self) -> PageInfoResult<()> {
        if self.initialized { return Ok(()); }
        self.pages.clear();
        self.initialized = true;
        Ok(())
    }

    fn add_page(&mut self, pa: PhysAddr, va: Option<VirtAddr>, flags: PageFlags) -> PageInfoResult<()> {
        let page_num = pa.as_u64() / layout::PAGE_SIZE as u64;
        if self.pages.len() >= MAX_TRACKED_PAGES { return Err(PageInfoError::TooManyPages); }
        let info = PageInfo::new(pa, va, flags);
        self.pages.insert(page_num, info);
        PAGE_STATS.increment_total();
        if va.is_some() { PAGE_STATS.increment_mapped(); }
        if flags.contains(PageFlags::DIRTY) { PAGE_STATS.increment_dirty(); }
        if flags.contains(PageFlags::LOCKED) { PAGE_STATS.increment_locked(); }
        Ok(())
    }

    fn remove_page(&mut self, pa: PhysAddr) -> PageInfoResult<()> {
        let page_num = pa.as_u64() / layout::PAGE_SIZE as u64;
        if let Some(info) = self.pages.remove(&page_num) {
            PAGE_STATS.decrement_total();
            if info.virtual_addr.is_some() { PAGE_STATS.decrement_mapped(); }
            if info.flags.contains(PageFlags::DIRTY) { PAGE_STATS.decrement_dirty(); }
            if info.flags.contains(PageFlags::LOCKED) { PAGE_STATS.decrement_locked(); }
            Ok(())
        } else {
            Err(PageInfoError::PageNotFound)
        }
    }

    fn get_page_info(&self, pa: PhysAddr) -> Option<PageInfo> {
        let page_num = pa.as_u64() / layout::PAGE_SIZE as u64;
        self.pages.get(&page_num).copied()
    }

    fn update_flags(&mut self, pa: PhysAddr, flags: PageFlags) -> PageInfoResult<()> {
        let page_num = pa.as_u64() / layout::PAGE_SIZE as u64;
        if let Some(info) = self.pages.get_mut(&page_num) {
            let old_flags = info.flags;
            info.flags = flags;
            info.last_access = get_timestamp();
            let was_dirty = old_flags.contains(PageFlags::DIRTY);
            let is_dirty = flags.contains(PageFlags::DIRTY);
            if was_dirty != is_dirty {
                if is_dirty { PAGE_STATS.increment_dirty(); } else { PAGE_STATS.decrement_dirty(); }
            }

            let was_locked = old_flags.contains(PageFlags::LOCKED);
            let is_locked = flags.contains(PageFlags::LOCKED);
            if was_locked != is_locked {
                if is_locked { PAGE_STATS.increment_locked(); } else { PAGE_STATS.decrement_locked(); }
            }

            PAGE_STATS.record_access();
            Ok(())
        } else {
            Err(PageInfoError::PageNotFound)
        }
    }

    fn increment_ref_count(&mut self, pa: PhysAddr) -> PageInfoResult<u32> {
        let page_num = pa.as_u64() / layout::PAGE_SIZE as u64;
        if let Some(info) = self.pages.get_mut(&page_num) {
            info.ref_count = info.ref_count.saturating_add(1);
            info.last_access = get_timestamp();
            Ok(info.ref_count)
        } else {
            Err(PageInfoError::PageNotFound)
        }
    }

    fn decrement_ref_count(&mut self, pa: PhysAddr) -> PageInfoResult<u32> {
        let page_num = pa.as_u64() / layout::PAGE_SIZE as u64;
        if let Some(info) = self.pages.get_mut(&page_num) {
            if info.ref_count == 0 { return Err(PageInfoError::RefCountUnderflow); }
            info.ref_count -= 1;
            info.last_access = get_timestamp();
            Ok(info.ref_count)
        } else {
            Err(PageInfoError::PageNotFound)
        }
    }
}

pub fn get_timestamp() -> u64 {
    // SAFETY: RDTSC is safe on all x86_64 CPUs
    unsafe { core::arch::x86_64::_rdtsc() }
}

pub fn init() -> PageInfoResult<()> {
    PAGE_INFO_MANAGER.lock().init()
}

pub fn add_page(pa: PhysAddr, va: Option<VirtAddr>, flags: PageFlags) -> PageInfoResult<()> {
    PAGE_INFO_MANAGER.lock().add_page(pa, va, flags)
}

pub fn remove_page(pa: PhysAddr) -> PageInfoResult<()> {
    PAGE_INFO_MANAGER.lock().remove_page(pa)
}

pub fn get_page_info(pa: PhysAddr) -> Option<PageInfo> {
    PAGE_INFO_MANAGER.lock().get_page_info(pa)
}

pub fn update_page_flags(pa: PhysAddr, flags: PageFlags) -> PageInfoResult<()> {
    PAGE_INFO_MANAGER.lock().update_flags(pa, flags)
}

pub fn increment_ref_count(pa: PhysAddr) -> PageInfoResult<u32> {
    PAGE_INFO_MANAGER.lock().increment_ref_count(pa)
}

pub fn decrement_ref_count(pa: PhysAddr) -> PageInfoResult<u32> {
    PAGE_INFO_MANAGER.lock().decrement_ref_count(pa)
}

pub fn get_page_stats() -> (usize, usize, usize, usize, u64) {
    (
        PAGE_STATS.total_pages.load(Ordering::Relaxed),
        PAGE_STATS.mapped_pages.load(Ordering::Relaxed),
        PAGE_STATS.dirty_pages.load(Ordering::Relaxed),
        PAGE_STATS.locked_pages.load(Ordering::Relaxed),
        PAGE_STATS.page_accesses.load(Ordering::Relaxed),
    )
}

pub fn get_stats_snapshot() -> PageStatsSnapshot {
    PageStatsSnapshot {
        total_pages: PAGE_STATS.total_pages.load(Ordering::Relaxed),
        mapped_pages: PAGE_STATS.mapped_pages.load(Ordering::Relaxed),
        dirty_pages: PAGE_STATS.dirty_pages.load(Ordering::Relaxed),
        locked_pages: PAGE_STATS.locked_pages.load(Ordering::Relaxed),
        page_accesses: PAGE_STATS.page_accesses.load(Ordering::Relaxed),
    }
}

pub fn page_count() -> usize {
    PAGE_STATS.total_pages.load(Ordering::Relaxed)
}

pub fn is_initialized() -> bool {
    PAGE_INFO_MANAGER.lock().initialized
}
