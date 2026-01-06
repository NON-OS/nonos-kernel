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

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use x86_64::{PhysAddr, VirtAddr};
use super::constants::*;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PageFlags {
    bits: u32,
}

impl PageFlags {
    pub const PRESENT: Self = Self { bits: 1 << flags::PRESENT_BIT };
    pub const WRITABLE: Self = Self { bits: 1 << flags::WRITABLE_BIT };
    pub const USER: Self = Self { bits: 1 << flags::USER_BIT };
    pub const DIRTY: Self = Self { bits: 1 << flags::DIRTY_BIT };
    pub const ACCESSED: Self = Self { bits: 1 << flags::ACCESSED_BIT };
    pub const LOCKED: Self = Self { bits: 1 << flags::LOCKED_BIT };
    pub const ENCRYPTED: Self = Self { bits: 1 << flags::ENCRYPTED_BIT };
    pub const EMPTY: Self = Self { bits: 0 };
    pub const fn from_bits(bits: u32) -> Self { Self { bits } }
    pub const fn bits(&self) -> u32 { self.bits }
    pub const fn contains(self, other: Self) -> bool { (self.bits & other.bits) == other.bits }
    pub const fn union(self, other: Self) -> Self { Self { bits: self.bits | other.bits } }
    pub const fn intersection(self, other: Self) -> Self { Self { bits: self.bits & other.bits } }
    pub const fn difference(self, other: Self) -> Self { Self { bits: self.bits & !other.bits } }
    pub const fn is_empty(self) -> bool { self.bits == 0 }
}

#[derive(Debug, Clone, Copy)]
pub struct PageInfo {
    pub physical_addr: PhysAddr,
    pub virtual_addr: Option<VirtAddr>,
    pub flags: PageFlags,
    pub ref_count: u32,
    pub allocation_time: u64,
    pub last_access: u64,
}

impl PageInfo {
    pub fn new(physical_addr: PhysAddr, virtual_addr: Option<VirtAddr>, flags: PageFlags) -> Self {
        let now = super::manager::get_timestamp();
        Self { physical_addr, virtual_addr, flags, ref_count: INITIAL_REF_COUNT, allocation_time: now, last_access: now }
    }

    pub fn is_mapped(&self) -> bool { self.virtual_addr.is_some() }
    pub fn is_dirty(&self) -> bool { self.flags.contains(PageFlags::DIRTY) }
    pub fn is_locked(&self) -> bool { self.flags.contains(PageFlags::LOCKED) }
}

pub struct PageStats {
    pub total_pages: AtomicUsize,
    pub mapped_pages: AtomicUsize,
    pub dirty_pages: AtomicUsize,
    pub locked_pages: AtomicUsize,
    pub page_accesses: AtomicU64,
}

impl PageStats {
    pub const fn new() -> Self {
        Self {
            total_pages: AtomicUsize::new(0),
            mapped_pages: AtomicUsize::new(0),
            dirty_pages: AtomicUsize::new(0),
            locked_pages: AtomicUsize::new(0),
            page_accesses: AtomicU64::new(0),
        }
    }

    pub fn increment_total(&self) { self.total_pages.fetch_add(1, Ordering::Relaxed); }
    pub fn decrement_total(&self) { self.total_pages.fetch_sub(1, Ordering::Relaxed); }
    pub fn increment_mapped(&self) { self.mapped_pages.fetch_add(1, Ordering::Relaxed); }
    pub fn decrement_mapped(&self) { self.mapped_pages.fetch_sub(1, Ordering::Relaxed); }
    pub fn increment_dirty(&self) { self.dirty_pages.fetch_add(1, Ordering::Relaxed); }
    pub fn decrement_dirty(&self) { self.dirty_pages.fetch_sub(1, Ordering::Relaxed); }
    pub fn increment_locked(&self) { self.locked_pages.fetch_add(1, Ordering::Relaxed); }
    pub fn decrement_locked(&self) { self.locked_pages.fetch_sub(1, Ordering::Relaxed); }
    pub fn record_access(&self) { self.page_accesses.fetch_add(1, Ordering::Relaxed); }
}

#[derive(Debug, Clone, Copy)]
pub struct PageStatsSnapshot {
    pub total_pages: usize,
    pub mapped_pages: usize,
    pub dirty_pages: usize,
    pub locked_pages: usize,
    pub page_accesses: u64,
}
