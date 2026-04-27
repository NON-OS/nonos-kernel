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
use super::repo::{repo_path, HEAD_FILE, REFS_HEADS, REFS_REMOTES};
use crate::fs::ramfs;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

pub(super) fn read_head(repo: &str) -> Option<String> {
    let data = ramfs::read_file(&repo_path(repo, HEAD_FILE)).ok()?;
    let s = core::str::from_utf8(&data).ok()?.trim();
    if s.starts_with("ref: ") {
        Some(String::from(&s[5..]))
    } else {
        Some(String::from(s))
    }
}

pub(super) fn write_head(repo: &str, reference: &str) -> Result<(), &'static str> {
    ramfs::write_file(&repo_path(repo, HEAD_FILE), format!("ref: {}\n", reference).as_bytes())
        .map_err(|_| "write HEAD")
}

pub(super) fn read_ref(repo: &str, ref_name: &str) -> Option<String> {
    let data = ramfs::read_file(&repo_path(repo, ref_name)).ok()?;
    Some(String::from(core::str::from_utf8(&data).ok()?.trim()))
}

pub(super) fn write_ref(repo: &str, ref_name: &str, hash: &str) -> Result<(), &'static str> {
    ramfs::write_file(&repo_path(repo, ref_name), format!("{}\n", hash).as_bytes())
        .map_err(|_| "write ref")
}

pub(super) fn list_branches(repo: &str) -> Vec<String> {
    ramfs::list_dir(&repo_path(repo, REFS_HEADS)).unwrap_or_default()
}

fn _list_remotes(repo: &str) -> Vec<String> {
    ramfs::list_dir(&repo_path(repo, REFS_REMOTES)).unwrap_or_default()
}

fn _resolve_ref(repo: &str, name: &str) -> Option<String> {
    if name.starts_with("refs/") {
        return read_ref(repo, name);
    }
    let branch_ref = format!("{}/{}", REFS_HEADS, name);
    if let Some(h) = read_ref(repo, &branch_ref) {
        return Some(h);
    }
    let head = read_head(repo)?;
    if head.starts_with("refs/") {
        read_ref(repo, &head)
    } else {
        Some(head)
    }
}

pub(super) fn head_commit(repo: &str) -> Option<String> {
    let head = read_head(repo)?;
    if head.starts_with("refs/") {
        read_ref(repo, &head)
    } else {
        Some(head)
    }
}
