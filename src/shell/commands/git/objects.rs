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
use super::repo::{repo_path, OBJECTS_DIR};
use crate::fs::ramfs;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

pub(super) fn hash_content(data: &[u8]) -> String {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{:016x}", h)
}

pub(super) fn object_path(repo: &str, hash: &str) -> String {
    repo_path(repo, &format!("{}/{}/{}", OBJECTS_DIR, &hash[..2], &hash[2..]))
}

pub(super) fn store_blob(repo: &str, data: &[u8]) -> Result<String, &'static str> {
    let hash = hash_content(data);
    let dir = repo_path(repo, &format!("{}/{}", OBJECTS_DIR, &hash[..2]));
    let _ = ramfs::create_dir(&dir);
    ramfs::create_file(&object_path(repo, &hash), data).map_err(|_| "store blob")?;
    Ok(hash)
}

pub(super) fn read_object(repo: &str, hash: &str) -> Result<Vec<u8>, &'static str> {
    ramfs::read_file(&object_path(repo, hash)).map_err(|_| "object not found")
}

pub(super) fn store_tree(repo: &str, entries: &[(String, String)]) -> Result<String, &'static str> {
    let content: String = entries.iter().map(|(n, h)| format!("{} {}\n", h, n)).collect();
    store_blob(repo, content.as_bytes())
}

pub(super) fn store_commit(
    repo: &str,
    tree: &str,
    parent: Option<&str>,
    msg: &str,
) -> Result<String, &'static str> {
    let p = parent.map_or(String::new(), |p| format!("parent {}\n", p));
    store_blob(repo, format!("tree {}\n{}message {}\n", tree, p, msg).as_bytes())
}

pub(super) fn parse_commit(data: &[u8]) -> Option<(String, Option<String>, String)> {
    let s = core::str::from_utf8(data).ok()?;
    let mut tree = None;
    let mut parent = None;
    let mut msg = None;
    for line in s.lines() {
        if line.starts_with("tree ") {
            tree = Some(String::from(&line[5..]));
        } else if line.starts_with("parent ") {
            parent = Some(String::from(&line[7..]));
        } else if line.starts_with("message ") {
            msg = Some(String::from(&line[8..]));
        }
    }
    Some((tree?, parent, msg?))
}
