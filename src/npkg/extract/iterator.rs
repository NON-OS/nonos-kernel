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

use super::super::error::{NpkgError, NpkgResult};
use super::types::{ArchiveEntry, PackageArchive, ENTRY_SYMLINK};
use alloc::string::String;

pub struct ArchiveIterator<'a> {
    pub(super) archive: &'a PackageArchive<'a>,
    pub(super) offset: usize,
    pub(super) remaining: u32,
}

impl<'a> Iterator for ArchiveIterator<'a> {
    type Item = NpkgResult<ArchiveEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        let data = self.archive.data;
        let offset = self.offset;
        if offset + 4 > data.len() {
            return Some(Err(NpkgError::ArchiveCorrupt(String::from("truncated entry"))));
        }
        let path_len = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
        let entry_type = data[offset + 2];
        if offset + 4 + path_len > data.len() {
            return Some(Err(NpkgError::ArchiveCorrupt(String::from("truncated path"))));
        }
        let path = match core::str::from_utf8(&data[offset + 4..offset + 4 + path_len]) {
            Ok(s) => String::from(s),
            Err(_) => return Some(Err(NpkgError::ArchiveCorrupt(String::from("invalid path")))),
        };
        let mut pos = offset + 4 + path_len;
        if pos + 48 > data.len() {
            return Some(Err(NpkgError::ArchiveCorrupt(String::from("truncated metadata"))));
        }
        let size = u64::from_le_bytes([
            data[pos],
            data[pos + 1],
            data[pos + 2],
            data[pos + 3],
            data[pos + 4],
            data[pos + 5],
            data[pos + 6],
            data[pos + 7],
        ]);
        pos += 8;
        let mode = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        pos += 4;
        let mut checksum = [0u8; 32];
        checksum.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;
        let data_offset = u64::from_le_bytes([
            data[pos],
            data[pos + 1],
            data[pos + 2],
            data[pos + 3],
            data[pos + 4],
            data[pos + 5],
            data[pos + 6],
            data[pos + 7],
        ]);
        pos += 8;
        let link_target = if entry_type == ENTRY_SYMLINK {
            let link_len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
            pos += 2;
            if pos + link_len > data.len() {
                return Some(Err(NpkgError::ArchiveCorrupt(String::from("truncated link"))));
            }
            match core::str::from_utf8(&data[pos..pos + link_len]) {
                Ok(s) => {
                    pos += link_len;
                    Some(String::from(s))
                }
                Err(_) => {
                    return Some(Err(NpkgError::ArchiveCorrupt(String::from("invalid link"))))
                }
            }
        } else {
            None
        };
        self.offset = pos;
        Some(Ok(ArchiveEntry { path, entry_type, size, mode, checksum, data_offset, link_target }))
    }
}
