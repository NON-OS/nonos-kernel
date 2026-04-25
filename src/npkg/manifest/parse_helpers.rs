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

use crate::npkg::types::{
    Dependency, DependencyKind, FilePermissions, PackageFile, VersionRequirement,
};
use alloc::string::String;
use alloc::vec::Vec;

pub(super) fn parse_dependency_line(line: &str) -> Option<Dependency> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    let mut kind = DependencyKind::Runtime;
    let mut line = line;
    if let Some(rest) = line.strip_prefix("optional:") {
        kind = DependencyKind::Optional;
        line = rest.trim();
    } else if let Some(rest) = line.strip_prefix("conflict:") {
        kind = DependencyKind::Conflict;
        line = rest.trim();
    } else if let Some(rest) = line.strip_prefix("replace:") {
        kind = DependencyKind::Replace;
        line = rest.trim();
    } else if let Some(rest) = line.strip_prefix("provide:") {
        kind = DependencyKind::Provide;
        line = rest.trim();
    }
    let (name, version, reason) = if let Some((spec, reason)) = line.split_once(':') {
        let (name, version) = parse_name_version(spec.trim());
        (name, version, Some(String::from(reason.trim())))
    } else {
        let (name, version) = parse_name_version(line);
        (name, version, None)
    };
    Some(Dependency { name: String::from(name), version, kind, reason })
}

pub(super) fn parse_name_version(s: &str) -> (&str, VersionRequirement) {
    for (i, c) in s.char_indices() {
        if c == '>' || c == '<' || c == '=' || c == '^' {
            let name = s[..i].trim();
            let version = VersionRequirement::parse(&s[i..]).unwrap_or(VersionRequirement::Any);
            return (name, version);
        }
    }
    (s.trim(), VersionRequirement::Any)
}

pub(super) fn parse_file_line(line: &str) -> Option<PackageFile> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.is_empty() {
        return None;
    }
    let path = String::from(parts[0]);
    let mut permissions = FilePermissions::default();
    let mut is_config = false;
    let mut is_directory = path.ends_with('/');
    for part in parts.iter().skip(1) {
        if *part == "config" {
            is_config = true;
        } else if *part == "dir" {
            is_directory = true;
            permissions = FilePermissions::directory();
        } else if *part == "exec" {
            permissions = FilePermissions::executable();
        } else if let Ok(mode) = u32::from_str_radix(part, 8) {
            permissions.mode = mode;
        }
    }
    Some(PackageFile { path, size: 0, checksum: [0u8; 32], permissions, is_config, is_directory })
}
