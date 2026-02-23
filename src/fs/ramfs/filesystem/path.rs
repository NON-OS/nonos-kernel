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

use alloc::string::String;
use alloc::vec::Vec;

use super::super::error::{FsError, FsResult};
use super::super::types::MAX_PATH_LEN;

pub(crate) fn validate_path(path: &str) -> FsResult<()> {
    if path.is_empty() {
        return Err(FsError::InvalidPath);
    }
    if path.len() > MAX_PATH_LEN {
        return Err(FsError::PathTooLong);
    }
    if path.bytes().any(|b| b == 0) {
        return Err(FsError::InvalidPath);
    }
    if path.contains("..") {
        return Err(FsError::InvalidPath);
    }
    Ok(())
}

pub fn normalize_path(path: &str) -> String {
    let mut components: Vec<&str> = Vec::new();

    for component in path.split('/') {
        match component {
            "" | "." => continue,
            ".." => {
                components.pop();
            }
            c => components.push(c),
        }
    }

    let mut result = String::with_capacity(path.len());
    if path.starts_with('/') {
        result.push('/');
    }

    for (i, component) in components.iter().enumerate() {
        if i > 0 {
            result.push('/');
        }
        result.push_str(component);
    }

    if result.is_empty() {
        result.push('/');
    }

    result
}
