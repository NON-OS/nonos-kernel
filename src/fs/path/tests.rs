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

use alloc::vec::Vec;

use super::components::components;
use super::join::{join, join_secure};
use super::normalize::normalize_path;
use super::parts::{extension, file_name, parent};
use super::validate::validate_path_secure;

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
    assert!(validate_path_secure("/foo/../../etc").is_ok());
    assert!(join_secure("/home/user", "../../../etc").is_err());
}
