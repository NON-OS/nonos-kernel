// NØNOS Operating System
// Copyright (C) 2024 NØNOS Contributors
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

#![no_std]

extern crate alloc;

use alloc::{string::String, string::ToString, vec::Vec};

// ============================================================================
// CONFIGURATION CONSTANTS
// ============================================================================

/// Maximum path length in bytes
pub const MAX_PATH_LEN: usize = 4096;

/// Maximum path component length (single directory/file name)
pub const MAX_COMPONENT_LEN: usize = 255;

/// Path separator character
pub const PATH_SEPARATOR: char = '/';

/// Current directory component
pub const CURRENT_DIR: &str = ".";

/// Parent directory component
pub const PARENT_DIR: &str = "..";

// ============================================================================
// STRUCTURED ERROR HANDLING
// ============================================================================

/// Path operation errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathError {
    /// Null pointer provided
    NullPointer,
    /// Path exceeds maximum length
    TooLong,
    /// Path contains invalid UTF-8 sequences
    InvalidUtf8,
    /// Path is empty
    Empty,
    /// Path contains null bytes
    ContainsNull,
    /// Path component too long
    ComponentTooLong,
    /// Invalid path characters
    InvalidCharacter,
    /// Path traversal attempt detected (escaping root)
    TraversalAttempt,
    /// Path is not absolute when required
    NotAbsolute,
    /// Path is not relative when required
    NotRelative,
}

impl PathError {
    /// Convert to errno-style negative integer
    pub const fn to_errno(self) -> i32 {
        match self {
            PathError::NullPointer => -14,        // EFAULT
            PathError::TooLong => -36,            // ENAMETOOLONG
            PathError::InvalidUtf8 => -22,        // EINVAL
            PathError::Empty => -22,              // EINVAL
            PathError::ContainsNull => -22,       // EINVAL
            PathError::ComponentTooLong => -36,   // ENAMETOOLONG
            PathError::InvalidCharacter => -22,   // EINVAL
            PathError::TraversalAttempt => -1,    // EPERM
            PathError::NotAbsolute => -22,        // EINVAL
            PathError::NotRelative => -22,        // EINVAL
        }
    }

    /// Get human-readable error message
    pub const fn as_str(self) -> &'static str {
        match self {
            PathError::NullPointer => "Null pointer",
            PathError::TooLong => "Path too long",
            PathError::InvalidUtf8 => "Invalid UTF-8 in path",
            PathError::Empty => "Empty path",
            PathError::ContainsNull => "Path contains null byte",
            PathError::ComponentTooLong => "Path component too long",
            PathError::InvalidCharacter => "Invalid character in path",
            PathError::TraversalAttempt => "Path traversal attempt",
            PathError::NotAbsolute => "Path is not absolute",
            PathError::NotRelative => "Path is not relative",
        }
    }
}

impl From<PathError> for &'static str {
    fn from(err: PathError) -> Self {
        err.as_str()
    }
}

/// Result type for path operations
pub type PathResult<T> = Result<T, PathError>;

// ============================================================================
// C STRING CONVERSION
// ============================================================================

/// Convert a null-terminated C string pointer to a Rust String.
///
/// # Safety
/// The caller must ensure `ptr` points to a valid, null-terminated string
/// or is null.
///
/// # Errors
/// - `PathError::NullPointer` if ptr is null
/// - `PathError::TooLong` if string exceeds MAX_PATH_LEN
/// - `PathError::InvalidUtf8` if bytes are not valid UTF-8
pub fn cstr_to_string(ptr: *const u8) -> PathResult<String> {
    if ptr.is_null() {
        return Err(PathError::NullPointer);
    }

    let mut bytes = Vec::with_capacity(256);
    let mut offset = 0usize;

    loop {
        // Safety: Caller guarantees ptr is valid
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

/// Convert a null-terminated C string with explicit length limit.
///
/// # Safety
/// The caller must ensure `ptr` points to valid memory for at least `max_len` bytes
/// or until a null terminator is found.
pub fn cstr_to_string_bounded(ptr: *const u8, max_len: usize) -> PathResult<String> {
    if ptr.is_null() {
        return Err(PathError::NullPointer);
    }

    let limit = max_len.min(MAX_PATH_LEN);
    let mut bytes = Vec::with_capacity(limit.min(256));
    let mut offset = 0usize;

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

// ============================================================================
// PATH VALIDATION
// ============================================================================

/// Validate a path string for common issues.
///
/// Checks for:
/// - Empty path
/// - Path too long
/// - Null bytes
/// - Component length limits
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

    // Check component lengths
    for component in path.split(PATH_SEPARATOR) {
        if component.len() > MAX_COMPONENT_LEN {
            return Err(PathError::ComponentTooLong);
        }
    }

    Ok(())
}

/// Validate path and check for traversal attacks.
///
/// Ensures the normalized path doesn't escape the root directory.
pub fn validate_path_secure(path: &str) -> PathResult<()> {
    validate_path(path)?;

    // Normalize and check for root escape
    let normalized = normalize_path(path);
    if normalized.starts_with("../") || normalized == ".." {
        return Err(PathError::TraversalAttempt);
    }

    Ok(())
}

/// Check if path is absolute (starts with /)
#[inline]
pub fn is_absolute(path: &str) -> bool {
    path.starts_with(PATH_SEPARATOR)
}

/// Check if path is relative (doesn't start with /)
#[inline]
pub fn is_relative(path: &str) -> bool {
    !path.is_empty() && !path.starts_with(PATH_SEPARATOR)
}

/// Require path to be absolute
pub fn require_absolute(path: &str) -> PathResult<&str> {
    if is_absolute(path) {
        Ok(path)
    } else {
        Err(PathError::NotAbsolute)
    }
}

/// Require path to be relative
pub fn require_relative(path: &str) -> PathResult<&str> {
    if is_relative(path) {
        Ok(path)
    } else {
        Err(PathError::NotRelative)
    }
}

// ============================================================================
// PATH NORMALIZATION
// ============================================================================

/// Normalize a path by resolving `.`, `..`, and multiple slashes.
///
/// Examples:
/// - `/foo/bar/../baz` → `/foo/baz`
/// - `/foo/./bar` → `/foo/bar`
/// - `/foo//bar` → `/foo/bar`
/// - `foo/bar/..` → `foo`
/// - `../foo` → `../foo` (preserved for relative paths)
pub fn normalize_path(path: &str) -> String {
    if path.is_empty() {
        return String::new();
    }

    let is_abs = is_absolute(path);
    let mut components: Vec<&str> = Vec::new();

    for component in path.split(PATH_SEPARATOR) {
        match component {
            "" | "." => {
                // Skip empty components and current-dir markers
            }
            ".." => {
                if is_abs {
                    // For absolute paths, just pop if possible (can't go above root)
                    components.pop();
                } else if components.last().map_or(true, |&c| c == "..") {
                    // For relative paths, keep ".." if at start or after other ".."
                    components.push("..");
                } else {
                    // Pop the previous component
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

    // Handle edge cases
    if result.is_empty() {
        if is_abs {
            return "/".to_string();
        } else {
            return ".".to_string();
        }
    }

    result
}

/// Normalize path and ensure it doesn't escape the given root.
///
/// Returns normalized path if valid, or error if traversal detected.
pub fn normalize_path_secure(path: &str, root: &str) -> PathResult<String> {
    let normalized = normalize_path(path);

    // For absolute paths, ensure they stay within root
    if is_absolute(path) {
        let norm_root = normalize_path(root);
        if !normalized.starts_with(&norm_root) {
            return Err(PathError::TraversalAttempt);
        }
    }

    Ok(normalized)
}

// ============================================================================
// PATH COMPONENTS
// ============================================================================

/// Get the parent directory of a path.
///
/// Examples:
/// - `/foo/bar` → `/foo`
/// - `/foo` → `/`
/// - `/` → `/`
/// - `foo/bar` → `foo`
/// - `foo` → `.`
pub fn parent(path: &str) -> &str {
    if path.is_empty() || path == "/" {
        return path;
    }

    // Remove trailing slash
    let path = path.trim_end_matches(PATH_SEPARATOR);

    match path.rfind(PATH_SEPARATOR) {
        Some(0) => "/",
        Some(pos) => &path[..pos],
        None => ".",
    }
}

/// Get the file name (last component) of a path.
///
/// Examples:
/// - `/foo/bar.txt` → `bar.txt`
/// - `/foo/bar/` → `bar`
/// - `/` → ``
/// - `foo.txt` → `foo.txt`
pub fn file_name(path: &str) -> &str {
    if path.is_empty() {
        return "";
    }

    // Remove trailing slash
    let path = path.trim_end_matches(PATH_SEPARATOR);

    if path.is_empty() || path == "/" {
        return "";
    }

    match path.rfind(PATH_SEPARATOR) {
        Some(pos) => &path[pos + 1..],
        None => path,
    }
}

/// Get the file extension if present.
///
/// Examples:
/// - `foo.txt` → `Some("txt")`
/// - `foo.tar.gz` → `Some("gz")`
/// - `foo` → `None`
/// - `.hidden` → `None`
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

/// Get the file stem (name without extension).
///
/// Examples:
/// - `foo.txt` → `foo`
/// - `foo.tar.gz` → `foo.tar`
/// - `foo` → `foo`
/// - `.hidden` → `.hidden`
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

// ============================================================================
// PATH JOINING
// ============================================================================

/// Join two path components.
///
/// If `child` is absolute, it replaces `parent` entirely.
/// Otherwise, `child` is appended to `parent`.
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

/// Join and normalize path components.
pub fn join_normalize(parent_path: &str, child: &str) -> String {
    normalize_path(&join(parent_path, child))
}

/// Join path components securely, preventing traversal.
pub fn join_secure(parent_path: &str, child: &str) -> PathResult<String> {
    if is_absolute(child) {
        return Err(PathError::TraversalAttempt);
    }

    let joined = join(parent_path, child);
    let normalized = normalize_path(&joined);
    let parent_normalized = normalize_path(parent_path);

    // Ensure result is still under parent
    if !normalized.starts_with(&parent_normalized) {
        return Err(PathError::TraversalAttempt);
    }

    Ok(normalized)
}

// ============================================================================
// PATH ITERATION
// ============================================================================

/// Iterator over path components.
pub struct Components<'a> {
    path: &'a str,
    position: usize,
    is_absolute: bool,
    yielded_root: bool,
}

impl<'a> Components<'a> {
    /// Create new component iterator.
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
        // Yield root for absolute paths
        if self.is_absolute && !self.yielded_root {
            self.yielded_root = true;
            self.position = 1; // Skip leading slash
            return Some("/");
        }

        // Skip separators
        while self.position < self.path.len() {
            if self.path.as_bytes()[self.position] != b'/' {
                break;
            }
            self.position += 1;
        }

        if self.position >= self.path.len() {
            return None;
        }

        // Find next separator
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

/// Get an iterator over path components.
pub fn components(path: &str) -> Components<'_> {
    Components::new(path)
}

/// Count the number of path components.
pub fn component_count(path: &str) -> usize {
    components(path).count()
}

// ============================================================================
// LEGACY API (for backward compatibility)
// ============================================================================

/// Legacy wrapper that returns &'static str errors.
pub fn cstr_to_string_legacy(ptr: *const u8) -> Result<String, &'static str> {
    cstr_to_string(ptr).map_err(|e| e.as_str())
}

// ============================================================================
// UNIT TESTS
// ============================================================================

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
        assert_eq!(c, vec!["/", "foo", "bar", "baz"]);

        let c: Vec<_> = components("foo/bar").collect();
        assert_eq!(c, vec!["foo", "bar"]);
    }

    #[test]
    fn test_traversal_detection() {
        assert!(validate_path_secure("../etc/passwd").is_err());
        assert!(validate_path_secure("/foo/../../etc").is_ok()); // Normalized stays in root
        assert!(join_secure("/home/user", "../../../etc").is_err());
    }
}
