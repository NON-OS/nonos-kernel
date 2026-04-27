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
use super::iterator::ArchiveIterator;
use super::types::{ArchiveEntry, PackageArchive, ENTRY_FILE, NPKG_MAGIC, NPKG_VERSION};
use alloc::string::String;
use alloc::vec::Vec;

impl<'a> PackageArchive<'a> {
    pub fn open(data: &'a [u8]) -> NpkgResult<Self> {
        if data.len() < 24 {
            return Err(NpkgError::ArchiveCorrupt(String::from("too small")));
        }
        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if magic != NPKG_MAGIC {
            return Err(NpkgError::ArchiveCorrupt(String::from("bad magic")));
        }
        let version = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        if version > NPKG_VERSION {
            return Err(NpkgError::ArchiveCorrupt(String::from("unsupported version")));
        }
        let file_count = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let entries_offset = u32::from_le_bytes([data[12], data[13], data[14], data[15]]) as usize;
        let data_offset = u32::from_le_bytes([data[16], data[17], data[18], data[19]]) as usize;
        if entries_offset >= data.len() || data_offset >= data.len() {
            return Err(NpkgError::ArchiveCorrupt(String::from("bad offsets")));
        }
        Ok(Self { data, version, file_count, entries_offset, data_offset })
    }

    pub fn file_count(&self) -> u32 {
        self.file_count
    }

    pub fn archive_version(&self) -> u32 {
        self.version
    }

    pub fn entries(&'a self) -> ArchiveIterator<'a> {
        ArchiveIterator { archive: self, offset: self.entries_offset, remaining: self.file_count }
    }

    pub fn read_file(&self, entry: &ArchiveEntry) -> NpkgResult<Vec<u8>> {
        if entry.entry_type != ENTRY_FILE {
            return Err(NpkgError::ExtractionFailed(String::from("not a file")));
        }
        let start = self.data_offset + entry.data_offset as usize;
        let end = start + entry.size as usize;
        if end > self.data.len() {
            return Err(NpkgError::ArchiveCorrupt(String::from("data out of bounds")));
        }
        let file_data = &self.data[start..end];
        let actual_checksum = crate::crypto::blake3::blake3_hash(file_data);
        if actual_checksum != entry.checksum {
            return Err(NpkgError::ChecksumMismatch(entry.path.clone()));
        }
        Ok(file_data.to_vec())
    }
}
