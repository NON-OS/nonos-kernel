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

use alloc::{string::String, string::ToString, vec::Vec};

use super::error::{PathError, PathResult};
use super::types::PATH_SEPARATOR;
use super::validate::is_absolute;

pub fn normalize_path(path: &str) -> String {
    if path.is_empty() {
        return String::new();
    }

    let is_abs = is_absolute(path);
    let mut components: Vec<&str> = Vec::new();

    for component in path.split(PATH_SEPARATOR) {
        match component {
            "" | "." => {}
            ".." => {
                if is_abs {
                    components.pop();
                } else if components.last().map_or(true, |&c| c == "..") {
                    components.push("..");
                } else {
                    components.pop();
                }
            }
            other => {
                components.push(other);
            }
        }
    }

    let mut result = String::with_capacity(path.len());

    if is_abs {
        result.push(PATH_SEPARATOR);
    }

    for (i, component) in components.iter().enumerate() {
        if i > 0 {
            result.push(PATH_SEPARATOR);
        }
        result.push_str(component);
    }

    if result.is_empty() {
        if is_abs {
            return "/".to_string();
        } else {
            return ".".to_string();
        }
    }

    result
}

pub fn normalize_path_secure(path: &str, root: &str) -> PathResult<String> {
    let normalized = normalize_path(path);

    if is_absolute(path) {
        let norm_root = normalize_path(root);
        if !normalized.starts_with(&norm_root) {
            return Err(PathError::TraversalAttempt);
        }
    }

    Ok(normalized)
}
