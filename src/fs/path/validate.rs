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

use super::error::{PathError, PathResult};
use super::normalize::normalize_path;
use super::types::{MAX_COMPONENT_LEN, MAX_PATH_LEN, PATH_SEPARATOR};

pub fn validate_path(path: &str) -> PathResult<()> {
    if path.is_empty() {
        return Err(PathError::Empty);
    }

    if path.len() > MAX_PATH_LEN {
        return Err(PathError::TooLong);
    }

    if path.bytes().any(|b| b == 0) {
        return Err(PathError::ContainsNull);
    }

    for component in path.split(PATH_SEPARATOR) {
        if component.len() > MAX_COMPONENT_LEN {
            return Err(PathError::ComponentTooLong);
        }
    }

    Ok(())
}

pub fn validate_path_secure(path: &str) -> PathResult<()> {
    validate_path(path)?;

    let normalized = normalize_path(path);
    if normalized.starts_with("../") || normalized == ".." {
        return Err(PathError::TraversalAttempt);
    }

    Ok(())
}

#[inline]
pub fn is_absolute(path: &str) -> bool {
    path.starts_with(PATH_SEPARATOR)
}

#[inline]
pub fn is_relative(path: &str) -> bool {
    !path.is_empty() && !path.starts_with(PATH_SEPARATOR)
}

pub fn require_absolute(path: &str) -> PathResult<&str> {
    if is_absolute(path) {
        Ok(path)
    } else {
        Err(PathError::NotAbsolute)
    }
}

pub fn require_relative(path: &str) -> PathResult<&str> {
    if is_relative(path) {
        Ok(path)
    } else {
        Err(PathError::NotRelative)
    }
}
