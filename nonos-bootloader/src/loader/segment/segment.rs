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

use crate::loader::errors::{LoaderError, LoaderResult};
use crate::loader::types::{memory, ph_flags, LoadedSegment};
use crate::log::logger::{log_debug, log_info};

#[derive(Debug, Clone, Copy)]
pub struct SegmentLoadInfo {
    pub source_offset: usize,
    pub source_size: usize,
    pub dest_addr: u64,
    pub mem_size: usize,
    pub flags: u32,
    pub loaded: bool,
}

impl SegmentLoadInfo {
    pub fn from_segment(segment: &LoadedSegment, base_addr: u64, virt_base: u64) -> Self {
        let relative_addr = segment.target_addr.saturating_sub(virt_base);
        let dest_addr = base_addr + relative_addr;

        Self {
            source_offset: segment.file_offset as usize,
            source_size: segment.file_size as usize,
            dest_addr,
            mem_size: segment.mem_size as usize,
            flags: segment.flags,
            loaded: false,
        }
    }

    pub fn bss_region(&self) -> Option<(u64, usize)> {
        if self.mem_size > self.source_size {
            let bss_start = self.dest_addr + self.source_size as u64;
            let bss_size = self.mem_size - self.source_size;
            Some((bss_start, bss_size))
        } else {
            None
        }
    }

    pub fn is_executable(&self) -> bool {
        (self.flags & ph_flags::PF_X) != 0
    }

    pub fn is_writable(&self) -> bool {
        (self.flags & ph_flags::PF_W) != 0
    }
}

pub unsafe fn load_segment(source: &[u8], info: &SegmentLoadInfo) -> LoaderResult<()> {
    let source_end = info
        .source_offset
        .checked_add(info.source_size)
        .ok_or(LoaderError::IntegerOverflow)?;

    if source_end > source.len() {
        return Err(LoaderError::SegmentOutOfBounds);
    }

    if info.source_size > 0 {
        let src_ptr = source.as_ptr().add(info.source_offset);
        let dst_ptr = info.dest_addr as *mut u8;

        core::ptr::copy_nonoverlapping(src_ptr, dst_ptr, info.source_size);

        log_debug("segment", "Copied segment data");
    }

    if let Some((bss_start, bss_size)) = info.bss_region() {
        let bss_ptr = bss_start as *mut u8;
        core::ptr::write_bytes(bss_ptr, 0, bss_size);

        log_debug("segment", "Zeroed BSS region");
    }

    Ok(())
}

pub unsafe fn load_all_segments(
    source: &[u8],
    segments: &[Option<LoadedSegment>],
    base_addr: u64,
    virt_base: u64,
) -> LoaderResult<usize> {
    let mut loaded_count = 0;

    for segment in segments.iter().flatten() {
        let info = SegmentLoadInfo::from_segment(segment, base_addr, virt_base);
        load_segment(source, &info)?;
        loaded_count += 1;
    }

    log_info("segment", "All segments loaded");

    Ok(loaded_count)
}

pub fn calculate_memory_bounds(
    segments: &[Option<LoadedSegment>],
) -> LoaderResult<(u64, u64, usize)> {
    let mut min_addr = u64::MAX;
    let mut max_addr = 0u64;

    for segment in segments.iter().flatten() {
        let start = segment.target_addr;
        let end = start
            .checked_add(segment.mem_size)
            .ok_or(LoaderError::IntegerOverflow)?;

        min_addr = min_addr.min(start);
        max_addr = max_addr.max(end);
    }

    if min_addr == u64::MAX {
        return Err(LoaderError::NoLoadableSegments);
    }

    let total_size = max_addr
        .checked_sub(min_addr)
        .ok_or(LoaderError::IntegerOverflow)? as usize;

    Ok((min_addr, max_addr, total_size))
}

pub fn check_segment_overlaps(segments: &[Option<LoadedSegment>]) -> LoaderResult<()> {
    let active_segments: alloc::vec::Vec<_> = segments.iter().flatten().collect();

    for i in 0..active_segments.len() {
        for j in (i + 1)..active_segments.len() {
            let a = active_segments[i];
            let b = active_segments[j];

            let a_end = a.target_addr + a.mem_size;
            let b_end = b.target_addr + b.mem_size;

            if a.target_addr < b_end && b.target_addr < a_end {
                return Err(LoaderError::SegmentOverlap);
            }
        }
    }

    Ok(())
}

pub fn validate_segment_addresses(segments: &[Option<LoadedSegment>]) -> LoaderResult<()> {
    for segment in segments.iter().flatten() {
        if segment.target_addr != 0 && segment.target_addr < memory::MIN_LOAD_ADDRESS {
            return Err(LoaderError::AddressOutOfRange);
        }

        let end_addr = segment
            .target_addr
            .checked_add(segment.mem_size)
            .ok_or(LoaderError::IntegerOverflow)?;

        if end_addr > memory::MAX_LOAD_ADDRESS {
            return Err(LoaderError::AddressOutOfRange);
        }
    }

    Ok(())
}

pub fn count_wx_violations(segments: &[Option<LoadedSegment>]) -> usize {
    segments.iter().flatten().filter(|s| s.has_wx()).count()
}

pub fn total_file_size(segments: &[Option<LoadedSegment>]) -> u64 {
    segments.iter().flatten().map(|s| s.file_size).sum()
}

pub fn total_memory_size(segments: &[Option<LoadedSegment>]) -> u64 {
    segments.iter().flatten().map(|s| s.mem_size).sum()
}

#[derive(Debug, Default)]
pub struct SegmentPermissions {
    pub read_only: usize,
    pub read_write: usize,
    pub read_execute: usize,
    pub read_write_execute: usize,
}

impl SegmentPermissions {
    pub fn from_segments(segments: &[Option<LoadedSegment>]) -> Self {
        let mut perms = Self::default();

        for segment in segments.iter().flatten() {
            let r = (segment.flags & ph_flags::PF_R) != 0;
            let w = (segment.flags & ph_flags::PF_W) != 0;
            let x = (segment.flags & ph_flags::PF_X) != 0;

            match (r, w, x) {
                (true, false, false) => perms.read_only += 1,
                (true, true, false) => perms.read_write += 1,
                (true, false, true) => perms.read_execute += 1,
                (true, true, true) => perms.read_write_execute += 1,
                _ => {}
            }
        }

        perms
    }

    pub fn has_wx_violations(&self) -> bool {
        self.read_write_execute > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_segment(addr: u64, file_size: u64, mem_size: u64, flags: u32) -> LoadedSegment {
        LoadedSegment {
            file_offset: 0,
            file_size,
            mem_size,
            target_addr: addr,
            alignment: 0x1000,
            flags,
        }
    }

    #[test]
    fn test_memory_bounds() {
        let segments = [
            Some(make_segment(0x100000, 0x1000, 0x2000, ph_flags::PF_R)),
            Some(make_segment(0x200000, 0x1000, 0x1000, ph_flags::PF_R)),
            None,
        ];

        let (min, max, size) = calculate_memory_bounds(&segments).unwrap();
        assert_eq!(min, 0x100000);
        assert_eq!(max, 0x201000);
        assert_eq!(size, 0x101000);
    }

    #[test]
    fn test_wx_violations() {
        let segments = [
            Some(make_segment(
                0x100000,
                0x1000,
                0x1000,
                ph_flags::PF_R | ph_flags::PF_X,
            )),
            Some(make_segment(
                0x200000,
                0x1000,
                0x1000,
                ph_flags::PF_R | ph_flags::PF_W | ph_flags::PF_X,
            )),
            None,
        ];

        assert_eq!(count_wx_violations(&segments), 1);
    }

    #[test]
    fn test_segment_overlaps() {
        let non_overlapping = [
            Some(make_segment(0x100000, 0x1000, 0x1000, ph_flags::PF_R)),
            Some(make_segment(0x101000, 0x1000, 0x1000, ph_flags::PF_R)),
            None,
        ];
        assert!(check_segment_overlaps(&non_overlapping).is_ok());

        let overlapping = [
            Some(make_segment(0x100000, 0x1000, 0x2000, ph_flags::PF_R)),
            Some(make_segment(0x101000, 0x1000, 0x1000, ph_flags::PF_R)),
            None,
        ];
        assert!(check_segment_overlaps(&overlapping).is_err());
    }
}
