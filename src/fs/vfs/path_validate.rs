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

use super::error::{VfsError, VfsResult};
use alloc::{string::String, vec::Vec};

pub fn validate_path(path: &str) -> VfsResult<()> {
    if path.is_empty() {
        return Err(VfsError::InvalidPath);
    }
    if path.contains('\0') {
        return Err(VfsError::InvalidPath);
    }
    for component in path.split('/') {
        if component == ".." {
            return Err(VfsError::PathTraversal);
        }
    }
    Ok(())
}

pub fn sanitize_path(path: &str) -> VfsResult<String> {
    validate_path(path)?;
    let mut components: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => continue,
            ".." => return Err(VfsError::PathTraversal),
            _ => components.push(part),
        }
    }
    let normalized = if path.starts_with('/') {
        let mut s = String::from("/");
        s.push_str(&components.join("/"));
        s
    } else {
        components.join("/")
    };
    Ok(normalized)
}

pub fn is_within_root(path: &str, root: &str) -> bool {
    match sanitize_path(path) {
        Ok(clean) => clean.starts_with(root) || root == "/",
        Err(_) => false,
    }
}

// Relative paths are rejected at this layer. CWD is owned by the
// caller's policy context, not by the VFS path validator.
pub fn resolve_path(path: &str) -> VfsResult<String> {
    if path.starts_with('/') {
        sanitize_path(path)
    } else {
        Err(VfsError::InvalidPath)
    }
}
