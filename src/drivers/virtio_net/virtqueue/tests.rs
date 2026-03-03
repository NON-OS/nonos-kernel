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

#[cfg(test)]
mod tests {
    use core::mem;

    use super::super::super::constants::*;
    use super::super::descriptors::VirtqDesc;

    #[test]
    fn test_virtq_desc_size() {
        assert_eq!(VirtqDesc::SIZE, 16);
        assert_eq!(mem::size_of::<VirtqDesc>(), 16);
    }

    #[test]
    fn test_virtq_desc_flags() {
        let mut desc = VirtqDesc::new();
        assert!(!desc.has_next());
        assert!(!desc.is_write());

        desc.flags = VIRTQ_DESC_F_NEXT;
        assert!(desc.has_next());

        desc.flags = VIRTQ_DESC_F_WRITE;
        assert!(desc.is_write());
    }

    #[test]
    fn test_virtq_desc_clear() {
        let mut desc = VirtqDesc {
            addr: 0x1234,
            len: 100,
            flags: VIRTQ_DESC_F_NEXT,
            next: 5,
        };
        desc.clear();
        assert_eq!(desc.addr, 0);
        assert_eq!(desc.len, 0);
        assert_eq!(desc.flags, 0);
        assert_eq!(desc.next, 0);
    }
}
