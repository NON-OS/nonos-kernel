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

use super::*;
use super::constants::*;
use super::error::PageInfoError;

// ============================================================================
// CONSTANTS TESTS
// ============================================================================

#[test]
fn test_flag_bit_positions() {
    assert_eq!(flags::PRESENT_BIT, 0);
    assert_eq!(flags::WRITABLE_BIT, 1);
    assert_eq!(flags::USER_BIT, 2);
    assert_eq!(flags::DIRTY_BIT, 3);
    assert_eq!(flags::ACCESSED_BIT, 4);
    assert_eq!(flags::LOCKED_BIT, 5);
    assert_eq!(flags::ENCRYPTED_BIT, 6);
}

#[test]
fn test_initial_ref_count() {
    assert_eq!(INITIAL_REF_COUNT, 1);
}

#[test]
fn test_page_size() {
    assert_eq!(PAGE_SIZE, 4096);
}

// ============================================================================
// ERROR TESTS
// ============================================================================

#[test]
fn test_error_display() {
    let err = PageInfoError::PageNotFound;
    assert_eq!(err.as_str(), "Page not found");
}

#[test]
fn test_error_recoverable() {
    assert!(PageInfoError::PageNotFound.is_recoverable());
    assert!(PageInfoError::PageAlreadyExists.is_recoverable());
    assert!(!PageInfoError::RefCountUnderflow.is_recoverable());
}

#[test]
fn test_error_from_string() {
    let err: PageInfoError = "Page not found".into();
    assert_eq!(err, PageInfoError::PageNotFound);
}

// ============================================================================
// PAGE FLAGS TESTS
// ============================================================================

#[test]
fn test_page_flags_constants() {
    assert_eq!(PageFlags::PRESENT.bits(), 1 << 0);
    assert_eq!(PageFlags::WRITABLE.bits(), 1 << 1);
    assert_eq!(PageFlags::USER.bits(), 1 << 2);
    assert_eq!(PageFlags::DIRTY.bits(), 1 << 3);
    assert_eq!(PageFlags::ACCESSED.bits(), 1 << 4);
    assert_eq!(PageFlags::LOCKED.bits(), 1 << 5);
    assert_eq!(PageFlags::ENCRYPTED.bits(), 1 << 6);
}

#[test]
fn test_page_flags_empty() {
    let flags = PageFlags::EMPTY;
    assert!(flags.is_empty());
    assert_eq!(flags.bits(), 0);
}

#[test]
fn test_page_flags_contains() {
    let flags = PageFlags::PRESENT.union(PageFlags::WRITABLE);
    assert!(flags.contains(PageFlags::PRESENT));
    assert!(flags.contains(PageFlags::WRITABLE));
    assert!(!flags.contains(PageFlags::USER));
}

#[test]
fn test_page_flags_union() {
    let flags = PageFlags::PRESENT.union(PageFlags::WRITABLE);
    assert_eq!(flags.bits(), 0b11);
}

#[test]
fn test_page_flags_intersection() {
    let flags1 = PageFlags::PRESENT.union(PageFlags::WRITABLE);
    let flags2 = PageFlags::WRITABLE.union(PageFlags::USER);
    let result = flags1.intersection(flags2);
    assert!(result.contains(PageFlags::WRITABLE));
    assert!(!result.contains(PageFlags::PRESENT));
    assert!(!result.contains(PageFlags::USER));
}

#[test]
fn test_page_flags_difference() {
    let flags = PageFlags::PRESENT.union(PageFlags::WRITABLE);
    let result = flags.difference(PageFlags::WRITABLE);
    assert!(result.contains(PageFlags::PRESENT));
    assert!(!result.contains(PageFlags::WRITABLE));
}

#[test]
fn test_page_flags_from_bits() {
    let flags = PageFlags::from_bits(0b101);
    assert!(flags.contains(PageFlags::PRESENT));
    assert!(!flags.contains(PageFlags::WRITABLE));
    assert!(flags.contains(PageFlags::USER));
}

// ============================================================================
// PAGE INFO TESTS
// ============================================================================

#[test]
fn test_page_info_new() {
    let pa = PhysAddr::new(0x1000);
    let va = Some(VirtAddr::new(0xFFFF_8000_0000_1000));
    let flags = PageFlags::PRESENT.union(PageFlags::WRITABLE);
    let info = PageInfo::new(pa, va, flags);
    assert_eq!(info.physical_addr, pa);
    assert_eq!(info.virtual_addr, va);
    assert_eq!(info.flags, flags);
    assert_eq!(info.ref_count, INITIAL_REF_COUNT);
    assert!(info.allocation_time > 0);
    assert!(info.last_access >= info.allocation_time);
}

#[test]
fn test_page_info_is_mapped() {
    let pa = PhysAddr::new(0x1000);
    let mapped = PageInfo::new(pa, Some(VirtAddr::new(0x1000)), PageFlags::PRESENT);
    assert!(mapped.is_mapped());
    let unmapped = PageInfo::new(pa, None, PageFlags::PRESENT);
    assert!(!unmapped.is_mapped());
}

#[test]
fn test_page_info_is_dirty() {
    let pa = PhysAddr::new(0x1000);
    let dirty = PageInfo::new(pa, None, PageFlags::DIRTY);
    assert!(dirty.is_dirty());
    let clean = PageInfo::new(pa, None, PageFlags::PRESENT);
    assert!(!clean.is_dirty());
}

#[test]
fn test_page_info_is_locked() {
    let pa = PhysAddr::new(0x1000);
    let locked = PageInfo::new(pa, None, PageFlags::LOCKED);
    assert!(locked.is_locked());
    let unlocked = PageInfo::new(pa, None, PageFlags::PRESENT);
    assert!(!unlocked.is_locked());
}

#[test]
fn test_page_stats_snapshot_default() {
    let snapshot = PageStatsSnapshot {
        total_pages: 0,
        mapped_pages: 0,
        dirty_pages: 0,
        locked_pages: 0,
        page_accesses: 0,
    };

    assert_eq!(snapshot.total_pages, 0);
    assert_eq!(snapshot.mapped_pages, 0);
    assert_eq!(snapshot.dirty_pages, 0);
    assert_eq!(snapshot.locked_pages, 0);
    assert_eq!(snapshot.page_accesses, 0);
}

#[test]
fn test_get_page_stats_returns_tuple() {
    let (total, mapped, dirty, locked, accesses) = get_page_stats();
    assert!(total >= 0);
    assert!(mapped >= 0);
    assert!(dirty >= 0);
    assert!(locked >= 0);
    assert!(accesses >= 0);
}
