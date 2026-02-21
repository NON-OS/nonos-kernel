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

pub const MAX_PATH_LEN: usize = 4096;
pub const MAX_COMPONENT_LEN: usize = 255;
pub const PATH_SEPARATOR: char = '/';
pub const CURRENT_DIR: &str = ".";
pub const PARENT_DIR: &str = "..";
pub fn cstr_to_string(ptr: *const u8) -> PathResult<String> {
    if ptr.is_null() {
        return Err(PathError::NullPointer);
    }

    let mut bytes = Vec::with_capacity(256);
    let mut offset = 0usize;
    loop {
        // ## Safety: Caller guarantees ptr is valid
        let byte = unsafe { core::ptr::read(ptr.add(offset)) };
        if byte == 0 {
            break;
        }

        if offset >= MAX_PATH_LEN {
            return Err(PathError::TooLong);
        }

        bytes.push(byte);
        offset += 1;
    }

    core::str::from_utf8(&bytes)
        .map(|s| s.to_string())
        .map_err(|_| PathError::InvalidUtf8)
}

pub fn cstr_to_string_bounded(ptr: *const u8, max_len: usize) -> PathResult<String> {
    if ptr.is_null() {
        return Err(PathError::NullPointer);
    }

    let limit = max_len.min(MAX_PATH_LEN);
    let mut bytes = Vec::with_capacity(limit.min(256));
    let mut offset = 0usize;
    /// # Safety  
    while offset < limit {
        let byte = unsafe { core::ptr::read(ptr.add(offset)) };
        if byte == 0 {
            break;
        }

        bytes.push(byte);
        offset += 1;
    }

    if offset >= limit {
        return Err(PathError::TooLong);
    }

    core::str::from_utf8(&bytes)
        .map(|s| s.to_string())
        .map_err(|_| PathError::InvalidUtf8)
}

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

pub fn normalize_path(path: &str) -> String {
    if path.is_empty() {
        return String::new();
    }

    let is_abs = is_absolute(path);
    let mut components: Vec<&str> = Vec::new();
    for component in path.split(PATH_SEPARATOR) {
        match component {
            "" | "." => {
            }
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

pub fn parent(path: &str) -> &str {
    if path.is_empty() || path == "/" {
        return path;
    }

    let path = path.trim_end_matches(PATH_SEPARATOR);
    match path.rfind(PATH_SEPARATOR) {
        Some(0) => "/",
        Some(pos) => &path[..pos],
        None => ".",
    }
}

pub fn file_name(path: &str) -> &str {
    if path.is_empty() {
        return "";
    }

    let path = path.trim_end_matches(PATH_SEPARATOR);
    if path.is_empty() || path == "/" {
        return "";
    }

    match path.rfind(PATH_SEPARATOR) {
        Some(pos) => &path[pos + 1..],
        None => path,
    }
}

pub fn extension(path: &str) -> Option<&str> {
    let name = file_name(path);
    if name.is_empty() || name.starts_with('.') {
        return None;
    }

    match name.rfind('.') {
        Some(pos) if pos > 0 => Some(&name[pos + 1..]),
        _ => None,
    }
}

pub fn file_stem(path: &str) -> &str {
    let name = file_name(path);
    if name.is_empty() || name.starts_with('.') {
        return name;
    }

    match name.rfind('.') {
        Some(pos) if pos > 0 => &name[..pos],
        _ => name,
    }
}


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

pub struct Components<'a> {
    path: &'a str,
    position: usize,
    is_absolute: bool,
    yielded_root: bool,
}

impl<'a> Components<'a> {
    pub fn new(path: &'a str) -> Self {
        Self {
            path,
            position: 0,
            is_absolute: is_absolute(path),
            yielded_root: false,
        }
    }
}

impl<'a> Iterator for Components<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        if self.is_absolute && !self.yielded_root {
            self.yielded_root = true;
            self.position = 1; // Skip leading slash
            return Some("/");
        }

        while self.position < self.path.len() {
            if self.path.as_bytes()[self.position] != b'/' {
                break;
            }
            self.position += 1;
        }

        if self.position >= self.path.len() {
            return None;
        }

        let start = self.position;
        while self.position < self.path.len() {
            if self.path.as_bytes()[self.position] == b'/' {
                break;
            }
            self.position += 1;
        }

        Some(&self.path[start..self.position])
    }
}

pub fn components(path: &str) -> Components<'_> {
    Components::new(path)
}

pub fn component_count(path: &str) -> usize {
    components(path).count()
}

pub fn cstr_to_string_legacy(ptr: *const u8) -> Result<String, &'static str> {
    cstr_to_string(ptr).map_err(|e| e.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_absolute() {
        assert_eq!(normalize_path("/foo/bar"), "/foo/bar");
        assert_eq!(normalize_path("/foo/./bar"), "/foo/bar");
        assert_eq!(normalize_path("/foo/../bar"), "/bar");
        assert_eq!(normalize_path("/foo/bar/.."), "/foo");
        assert_eq!(normalize_path("//foo//bar//"), "/foo/bar");
        assert_eq!(normalize_path("/"), "/");
        assert_eq!(normalize_path("/.."), "/");
    }

    #[test]
    fn test_normalize_relative() {
        assert_eq!(normalize_path("foo/bar"), "foo/bar");
        assert_eq!(normalize_path("foo/./bar"), "foo/bar");
        assert_eq!(normalize_path("foo/../bar"), "bar");
        assert_eq!(normalize_path("../foo"), "../foo");
        assert_eq!(normalize_path("../../foo"), "../../foo");
        assert_eq!(normalize_path("foo/.."), ".");
        assert_eq!(normalize_path("."), ".");
    }

    #[test]
    fn test_parent() {
        assert_eq!(parent("/foo/bar"), "/foo");
        assert_eq!(parent("/foo"), "/");
        assert_eq!(parent("/"), "/");
        assert_eq!(parent("foo/bar"), "foo");
        assert_eq!(parent("foo"), ".");
    }

    #[test]
    fn test_file_name() {
        assert_eq!(file_name("/foo/bar.txt"), "bar.txt");
        assert_eq!(file_name("/foo/bar/"), "bar");
        assert_eq!(file_name("/"), "");
        assert_eq!(file_name("foo.txt"), "foo.txt");
    }

    #[test]
    fn test_extension() {
        assert_eq!(extension("foo.txt"), Some("txt"));
        assert_eq!(extension("foo.tar.gz"), Some("gz"));
        assert_eq!(extension("foo"), None);
        assert_eq!(extension(".hidden"), None);
    }

    #[test]
    fn test_join() {
        assert_eq!(join("/foo", "bar"), "/foo/bar");
        assert_eq!(join("/foo/", "bar"), "/foo/bar");
        assert_eq!(join("/foo", "/bar"), "/bar");
        assert_eq!(join("", "bar"), "bar");
    }

    #[test]
    fn test_components() {
        let c: Vec<_> = components("/foo/bar/baz").collect();
        assert_eq!(c, alloc::vec!["/", "foo", "bar", "baz"]);

        let c: Vec<_> = components("foo/bar").collect();
        assert_eq!(c, alloc::vec!["foo", "bar"]);
    }

    #[test]
    fn test_traversal_detection() {
        assert!(validate_path_secure("../etc/passwd").is_err());
        assert!(validate_path_secure("/foo/../../etc").is_ok()); // Normalized stays in root
        assert!(join_secure("/home/user", "../../../etc").is_err());
    }
}
