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

use crate::loader::types::{ph_flags, LoadedSegment};

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
