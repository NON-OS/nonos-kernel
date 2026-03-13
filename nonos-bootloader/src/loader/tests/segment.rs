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

use crate::loader::*;

#[test]
fn test_segment_permissions() {
    let segments = [
        Some(types::LoadedSegment {
            file_offset: 0,
            file_size: 0x1000,
            mem_size: 0x1000,
            target_addr: 0x100000,
            alignment: 0x1000,
            flags: types::ph_flags::PF_R | types::ph_flags::PF_X,
        }),
        Some(types::LoadedSegment {
            file_offset: 0x1000,
            file_size: 0x1000,
            mem_size: 0x2000,
            target_addr: 0x200000,
            alignment: 0x1000,
            flags: types::ph_flags::PF_R | types::ph_flags::PF_W,
        }),
        None,
    ];

    let perms = segment::SegmentPermissions::from_segments(&segments);
    assert_eq!(perms.read_execute, 1);
    assert_eq!(perms.read_write, 1);
    assert!(!perms.has_wx_violations());
}
