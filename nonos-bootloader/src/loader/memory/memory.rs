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

pub use super::ops::{
    allocate_anywhere, allocate_at_address, allocate_below_4gb, copy_memory, is_page_aligned,
    page_align_down, page_align_up, pages_for_size, zero_memory,
};
pub use super::record::{AllocationRecord, MemoryRegion};
pub use super::table::AllocationTable;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allocation_table() {
        let mut table = AllocationTable::new();
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);

        table.record(0x1000, 1).unwrap();
        assert!(!table.is_empty());
        assert_eq!(table.len(), 1);
        assert_eq!(table.total_pages(), 1);
    }

    #[test]
    fn test_page_alignment() {
        assert_eq!(page_align_down(0x1234), 0x1000);
        assert_eq!(page_align_up(0x1234), 0x2000);
        assert!(is_page_aligned(0x1000));
        assert!(!is_page_aligned(0x1234));
    }

    #[test]
    fn test_pages_for_size() {
        assert_eq!(pages_for_size(0), 0);
        assert_eq!(pages_for_size(1), 1);
        assert_eq!(pages_for_size(0x1000), 1);
        assert_eq!(pages_for_size(0x1001), 2);
    }

    #[test]
    fn test_memory_region() {
        let region = MemoryRegion {
            start: 0x1000,
            size: 0x2000,
            writable: true,
            executable: false,
        };

        assert!(region.contains(0x1000));
        assert!(region.contains(0x2FFF));
        assert!(!region.contains(0x3000));
        assert_eq!(region.end(), 0x3000);
    }
}
