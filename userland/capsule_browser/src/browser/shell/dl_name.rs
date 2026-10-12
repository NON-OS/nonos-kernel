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

use alloc::format;
use alloc::string::String;

/// The last path segment of `url`, ignoring its query and fragment, or
/// empty when the URL has no path.
fn last_segment(url: &str) -> &str {
    let bare = url.split(['?', '#']).next().unwrap_or("");
    let rest = bare.split_once("://").map_or(bare, |(_, r)| r);
    rest.split_once('/').map_or("", |(_, path)| path.rsplit('/').next().unwrap_or(""))
}

/// A file name for `url`: its last path segment with `/` and control bytes
/// replaced by `_`, or `download` when that is empty, `.` or `..`.
pub fn name_of(url: &str) -> String {
    let seg = last_segment(url);
    if seg.is_empty() || seg == "." || seg == ".." {
        return String::from("download");
    }
    seg.chars().map(|c| if c == '/' || c.is_control() { '_' } else { c }).collect()
}

/// `name` when no entry of `existing` has it, otherwise the first free of
/// `stem (2).ext`, `stem (3).ext`, ... A leading dot does not start an
/// extension, so `.x` becomes `.x (2)`.
pub fn unique_name(existing: &[String], name: &str) -> String {
    let taken = |c: &str| existing.iter().any(|e| e == c);
    if !taken(name) {
        return String::from(name);
    }
    let (stem, ext) = match name.rfind('.') {
        Some(i) if i > 0 => name.split_at(i),
        _ => (name, ""),
    };
    (2u32..).map(|n| format!("{} ({}){}", stem, n, ext)).find(|c| !taken(c)).unwrap_or_default()
}
