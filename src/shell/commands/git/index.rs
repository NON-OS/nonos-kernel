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

extern crate alloc;
use super::repo::{repo_path, INDEX_FILE};
use crate::fs::ramfs;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

pub(super) struct IndexEntry {
    pub path: String,
    pub hash: String,
}

pub(super) fn read_index(repo: &str) -> Vec<IndexEntry> {
    let data = match ramfs::read_file(&repo_path(repo, INDEX_FILE)) {
        Ok(d) => d,
        Err(_) => return Vec::new(),
    };
    let content = match core::str::from_utf8(&data) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    content
        .lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.splitn(2, ' ').collect();
            if parts.len() == 2 {
                Some(IndexEntry { hash: String::from(parts[0]), path: String::from(parts[1]) })
            } else {
                None
            }
        })
        .collect()
}

pub(super) fn write_index(repo: &str, entries: &[IndexEntry]) -> Result<(), &'static str> {
    let content: String = entries.iter().map(|e| format!("{} {}\n", e.hash, e.path)).collect();
    ramfs::write_file(&repo_path(repo, INDEX_FILE), content.as_bytes()).map_err(|_| "write index")
}

pub(super) fn add_to_index(repo: &str, path: &str, hash: &str) -> Result<(), &'static str> {
    let mut entries = read_index(repo);
    entries.retain(|e| e.path != path);
    entries.push(IndexEntry { path: String::from(path), hash: String::from(hash) });
    write_index(repo, &entries)
}

pub(super) fn clear_index(repo: &str) -> Result<(), &'static str> {
    write_index(repo, &[])
}
