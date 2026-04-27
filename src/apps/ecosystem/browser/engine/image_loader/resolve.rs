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

use alloc::string::String;

pub fn resolve_url(src: &str, base_url: &str) -> Option<String> {
    let src = src.trim();
    if src.is_empty() {
        return None;
    }
    if src.starts_with("http://") || src.starts_with("https://") {
        return Some(String::from(src));
    }
    if src.starts_with("data:") {
        return None;
    }
    if src.starts_with("//") {
        let scheme = if base_url.starts_with("https") { "https:" } else { "http:" };
        return Some(alloc::format!("{}{}", scheme, src));
    }
    if src.starts_with('/') {
        let origin = extract_origin(base_url)?;
        return Some(alloc::format!("{}{}", origin, src));
    }
    let base_path = extract_base_path(base_url)?;
    Some(alloc::format!("{}{}", base_path, src))
}

fn extract_origin(url: &str) -> Option<String> {
    let scheme_end = url.find("://")?;
    let after_scheme = scheme_end + 3;
    let host_end = url[after_scheme..].find('/').map(|i| i + after_scheme).unwrap_or(url.len());
    Some(String::from(&url[..host_end]))
}

fn extract_base_path(url: &str) -> Option<String> {
    let scheme_end = url.find("://")?;
    let after_scheme = scheme_end + 3;
    let path_start = url[after_scheme..].find('/').map(|i| i + after_scheme)?;
    let last_slash = url[path_start..].rfind('/').map(|i| i + path_start)?;
    Some(String::from(&url[..last_slash + 1]))
}
