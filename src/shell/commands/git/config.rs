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
use super::repo::{repo_path, CONFIG_FILE};
use crate::fs::ramfs;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

pub(super) fn read_config(repo: &str) -> Vec<(String, String)> {
    let data = match ramfs::read_file(&repo_path(repo, CONFIG_FILE)) {
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
            let t = line.trim();
            if t.starts_with('[') || t.is_empty() {
                return None;
            }
            let parts: Vec<&str> = t.splitn(2, '=').collect();
            if parts.len() == 2 {
                Some((String::from(parts[0].trim()), String::from(parts[1].trim())))
            } else {
                None
            }
        })
        .collect()
}

pub(super) fn get_config(repo: &str, key: &str) -> Option<String> {
    read_config(repo).into_iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

pub(super) fn set_config(repo: &str, key: &str, value: &str) -> Result<(), &'static str> {
    let mut entries = read_config(repo);
    entries.retain(|(k, _)| k != key);
    entries.push((String::from(key), String::from(value)));
    let content: String = entries.iter().map(|(k, v)| format!("\t{} = {}\n", k, v)).collect();
    ramfs::write_file(&repo_path(repo, CONFIG_FILE), format!("[core]\n{}", content).as_bytes())
        .map_err(|_| "write config")
}

pub(super) fn get_remote_url(repo: &str, name: &str) -> Option<String> {
    get_config(repo, &format!("remote.{}.url", name))
}

pub(super) fn set_remote_url(repo: &str, name: &str, url: &str) -> Result<(), &'static str> {
    set_config(repo, &format!("remote.{}.url", name), url)
}
