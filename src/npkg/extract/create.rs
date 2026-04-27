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

use super::types::{ENTRY_DIR, ENTRY_FILE, ENTRY_SYMLINK, NPKG_MAGIC, NPKG_VERSION};
use alloc::string::String;
use alloc::vec::Vec;

pub fn create_package_archive(
    files: &[(String, Vec<u8>, u32)],
    dirs: &[(String, u32)],
    symlinks: &[(String, String)],
) -> Vec<u8> {
    let mut entries_data = Vec::new();
    let mut file_data = Vec::new();
    let mut file_offset = 0u64;
    for (path, mode) in dirs {
        entries_data.extend_from_slice(&(path.len() as u16).to_le_bytes());
        entries_data.push(ENTRY_DIR);
        entries_data.push(0);
        entries_data.extend_from_slice(path.as_bytes());
        entries_data.extend_from_slice(&0u64.to_le_bytes());
        entries_data.extend_from_slice(&mode.to_le_bytes());
        entries_data.extend_from_slice(&[0u8; 32]);
        entries_data.extend_from_slice(&0u64.to_le_bytes());
    }
    for (path, data, mode) in files {
        let checksum = crate::crypto::blake3::blake3_hash(data);
        entries_data.extend_from_slice(&(path.len() as u16).to_le_bytes());
        entries_data.push(ENTRY_FILE);
        entries_data.push(0);
        entries_data.extend_from_slice(path.as_bytes());
        entries_data.extend_from_slice(&(data.len() as u64).to_le_bytes());
        entries_data.extend_from_slice(&mode.to_le_bytes());
        entries_data.extend_from_slice(&checksum);
        entries_data.extend_from_slice(&file_offset.to_le_bytes());
        file_data.extend_from_slice(data);
        file_offset += data.len() as u64;
    }
    for (path, target) in symlinks {
        entries_data.extend_from_slice(&(path.len() as u16).to_le_bytes());
        entries_data.push(ENTRY_SYMLINK);
        entries_data.push(0);
        entries_data.extend_from_slice(path.as_bytes());
        entries_data.extend_from_slice(&0u64.to_le_bytes());
        entries_data.extend_from_slice(&0o777u32.to_le_bytes());
        entries_data.extend_from_slice(&[0u8; 32]);
        entries_data.extend_from_slice(&0u64.to_le_bytes());
        entries_data.extend_from_slice(&(target.len() as u16).to_le_bytes());
        entries_data.extend_from_slice(target.as_bytes());
    }
    let file_count = (dirs.len() + files.len() + symlinks.len()) as u32;
    let entries_offset = 24u32;
    let data_offset = entries_offset + entries_data.len() as u32;
    let mut archive = Vec::new();
    archive.extend_from_slice(&NPKG_MAGIC.to_le_bytes());
    archive.extend_from_slice(&NPKG_VERSION.to_le_bytes());
    archive.extend_from_slice(&file_count.to_le_bytes());
    archive.extend_from_slice(&entries_offset.to_le_bytes());
    archive.extend_from_slice(&data_offset.to_le_bytes());
    archive.extend_from_slice(&[0u8; 4]);
    archive.extend_from_slice(&entries_data);
    archive.extend_from_slice(&file_data);
    archive
}
