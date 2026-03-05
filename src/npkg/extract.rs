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

use alloc::string::String;
use alloc::vec::Vec;
use super::error::{NpkgError, NpkgResult};

const NPKG_MAGIC: u32 = 0x4E504B47;
const NPKG_VERSION: u32 = 1;

const ENTRY_FILE: u8 = 0;
const ENTRY_DIR: u8 = 1;
const ENTRY_SYMLINK: u8 = 2;

pub struct PackageArchive<'a> {
    data: &'a [u8],
    pub(crate) version: u32,
    file_count: u32,
    entries_offset: usize,
    data_offset: usize,
}

#[derive(Debug, Clone)]
pub struct ArchiveEntry {
    pub path: String,
    pub entry_type: u8,
    pub size: u64,
    pub mode: u32,
    pub checksum: [u8; 32],
    pub data_offset: u64,
    pub link_target: Option<String>,
}

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

        Ok(Self {
            data,
            version,
            file_count,
            entries_offset,
            data_offset,
        })
    }

    pub fn file_count(&self) -> u32 {
        self.file_count
    }

    pub fn archive_version(&self) -> u32 {
        self.version
    }

    pub fn entries(&'a self) -> ArchiveIterator<'a> {
        ArchiveIterator {
            archive: self,
            offset: self.entries_offset,
            remaining: self.file_count,
        }
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

pub struct ArchiveIterator<'a> {
    archive: &'a PackageArchive<'a>,
    offset: usize,
    remaining: u32,
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
            data[pos], data[pos + 1], data[pos + 2], data[pos + 3],
            data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7],
        ]);
        pos += 8;

        let mode = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        pos += 4;

        let mut checksum = [0u8; 32];
        checksum.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;

        let data_offset = u64::from_le_bytes([
            data[pos], data[pos + 1], data[pos + 2], data[pos + 3],
            data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7],
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
                Err(_) => return Some(Err(NpkgError::ArchiveCorrupt(String::from("invalid link")))),
            }
        } else {
            None
        };

        self.offset = pos;

        Some(Ok(ArchiveEntry {
            path,
            entry_type,
            size,
            mode,
            checksum,
            data_offset,
            link_target,
        }))
    }
}

pub fn extract_package(archive: &PackageArchive, dest: &str) -> NpkgResult<Vec<String>> {
    let mut installed_files = Vec::new();

    for entry_result in archive.entries() {
        let entry = entry_result?;

        let full_path = if dest == "/" {
            entry.path.clone()
        } else {
            alloc::format!("{}{}", dest.trim_end_matches('/'), entry.path)
        };

        match entry.entry_type {
            ENTRY_DIR => {
                create_directory(&full_path, entry.mode)?;
            }
            ENTRY_FILE => {
                let data = archive.read_file(&entry)?;
                create_file(&full_path, &data, entry.mode)?;
            }
            ENTRY_SYMLINK => {
                if let Some(ref target) = entry.link_target {
                    create_symlink(&full_path, target)?;
                }
            }
            _ => {
                return Err(NpkgError::ExtractionFailed(alloc::format!(
                    "unknown entry type: {}",
                    entry.entry_type
                )));
            }
        }

        installed_files.push(full_path);
    }

    Ok(installed_files)
}

fn create_directory(path: &str, mode: u32) -> NpkgResult<()> {
    let components: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    let mut current = String::new();
    for component in components {
        current.push('/');
        current.push_str(component);

        if !directory_exists(&current) {
            crate::fs::mkdir(&current, mode)
                .map_err(|_| NpkgError::ExtractionFailed(alloc::format!("mkdir failed: {}", current)))?;
        }
    }

    Ok(())
}

fn create_file(path: &str, data: &[u8], mode: u32) -> NpkgResult<()> {
    if let Some(parent) = parent_directory(path) {
        if !directory_exists(&parent) {
            create_directory(&parent, 0o755)?;
        }
    }

    crate::fs::nonos_vfs::vfs_write_file(path, data)
        .map_err(|_| NpkgError::ExtractionFailed(alloc::format!("write failed: {}", path)))?;

    let _ = crate::fs::chmod(path, mode);

    Ok(())
}

fn create_symlink(path: &str, target: &str) -> NpkgResult<()> {
    if let Some(parent) = parent_directory(path) {
        if !directory_exists(&parent) {
            create_directory(&parent, 0o755)?;
        }
    }

    crate::fs::symlink(target, path)
        .map_err(|_| NpkgError::ExtractionFailed(alloc::format!("symlink failed: {}", path)))?;

    Ok(())
}

fn directory_exists(path: &str) -> bool {
    crate::fs::is_directory(path)
}

fn parent_directory(path: &str) -> Option<String> {
    let path = path.trim_end_matches('/');
    path.rfind('/').map(|idx| {
        if idx == 0 {
            String::from("/")
        } else {
            String::from(&path[..idx])
        }
    })
}

pub fn list_package_contents(archive: &PackageArchive) -> NpkgResult<Vec<ArchiveEntry>> {
    let mut entries = Vec::new();

    for entry_result in archive.entries() {
        entries.push(entry_result?);
    }

    Ok(entries)
}

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
