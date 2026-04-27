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
use crate::fs::ramfs;
use alloc::format;
use alloc::string::String;
use spin::RwLock;

pub(super) const GIT_DIR: &str = ".git";
pub(super) const HEAD_FILE: &str = ".git/HEAD";
pub(super) const CONFIG_FILE: &str = ".git/config";
pub(super) const INDEX_FILE: &str = ".git/index";
pub(super) const OBJECTS_DIR: &str = ".git/objects";
pub(super) const REFS_HEADS: &str = ".git/refs/heads";
pub(super) const REFS_REMOTES: &str = ".git/refs/remotes";

static CURRENT_REPO: RwLock<Option<String>> = RwLock::new(None);

pub(super) fn set_repo(path: &str) {
    *CURRENT_REPO.write() = Some(String::from(path));
}
pub(super) fn repo_path(base: &str, sub: &str) -> String {
    if base.ends_with('/') {
        format!("{}{}", base, sub)
    } else {
        format!("{}/{}", base, sub)
    }
}

pub(super) fn is_repo(path: &str) -> bool {
    ramfs::exists(&repo_path(path, HEAD_FILE))
}

pub(super) fn init(path: &str) -> Result<(), &'static str> {
    let dirs = [GIT_DIR, OBJECTS_DIR, ".git/refs", REFS_HEADS, REFS_REMOTES];
    for d in dirs {
        ramfs::create_dir(&repo_path(path, d)).map_err(|_| "mkdir failed")?;
    }
    ramfs::create_file(&repo_path(path, HEAD_FILE), b"ref: refs/heads/main\n")
        .map_err(|_| "HEAD")?;
    ramfs::create_file(&repo_path(path, CONFIG_FILE), b"[core]\n\tbare = false\n")
        .map_err(|_| "config")?;
    ramfs::create_file(&repo_path(path, INDEX_FILE), b"").map_err(|_| "index")?;
    set_repo(path);
    Ok(())
}

pub(super) fn current_branch(path: &str) -> Option<String> {
    let data = ramfs::read_file(&repo_path(path, HEAD_FILE)).ok()?;
    let s = core::str::from_utf8(&data).ok()?.trim();
    if s.starts_with("ref: refs/heads/") {
        Some(String::from(&s[16..]))
    } else {
        None
    }
}
