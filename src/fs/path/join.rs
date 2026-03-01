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

use alloc::{string::String, string::ToString};

use super::error::{PathError, PathResult};
use super::normalize::normalize_path;
use super::types::PATH_SEPARATOR;
use super::validate::is_absolute;

pub fn join(parent_path: &str, child: &str) -> String {
    if child.is_empty() {
        return parent_path.to_string();
    }

    if is_absolute(child) {
        return child.to_string();
    }

    if parent_path.is_empty() {
        return child.to_string();
    }

    let mut result = String::with_capacity(parent_path.len() + 1 + child.len());
    result.push_str(parent_path);

    if !parent_path.ends_with(PATH_SEPARATOR) {
        result.push(PATH_SEPARATOR);
    }

    result.push_str(child);
    result
}

pub fn join_normalize(parent_path: &str, child: &str) -> String {
    normalize_path(&join(parent_path, child))
}

pub fn join_secure(parent_path: &str, child: &str) -> PathResult<String> {
    if is_absolute(child) {
        return Err(PathError::TraversalAttempt);
    }

    let joined = join(parent_path, child);
    let normalized = normalize_path(&joined);
    let parent_normalized = normalize_path(parent_path);

    if !normalized.starts_with(&parent_normalized) {
        return Err(PathError::TraversalAttempt);
    }

    Ok(normalized)
}
