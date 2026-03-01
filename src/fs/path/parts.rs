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

use super::types::PATH_SEPARATOR;

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
