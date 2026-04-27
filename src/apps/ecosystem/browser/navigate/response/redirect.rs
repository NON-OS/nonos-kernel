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

use super::parse::find_header_end;
use alloc::string::String;

pub(super) fn extract_redirect(data: &[u8], base_url: &str) -> Option<String> {
    let header_end = find_header_end(data)?;
    let headers = core::str::from_utf8(&data[..header_end]).ok()?;
    let status_line = headers.lines().next()?;
    let is_redirect = status_line.contains(" 301 ")
        || status_line.contains(" 302 ")
        || status_line.contains(" 303 ")
        || status_line.contains(" 307 ")
        || status_line.contains(" 308 ");
    if !is_redirect {
        return None;
    }
    for line in headers.lines().skip(1) {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("location:") {
            let location = line[9..].trim();
            if location.starts_with("http://") || location.starts_with("https://") {
                return Some(String::from(location));
            }
            return Some(resolve_relative_url(base_url, location));
        }
    }
    None
}

pub(super) fn resolve_relative_url(base: &str, relative: &str) -> String {
    if relative.starts_with('/') {
        let scheme_end = base.find("://").map(|i| i + 3).unwrap_or(0);
        let host_end = base[scheme_end..].find('/').map(|i| i + scheme_end).unwrap_or(base.len());
        let mut result = String::from(&base[..host_end]);
        result.push_str(relative);
        return result;
    }
    String::from(relative)
}

pub(super) fn resolve_noscript_redirect(base: &str, redirect: &str) -> String {
    if redirect.starts_with("http://") || redirect.starts_with("https://") {
        return String::from(redirect);
    }
    if redirect.starts_with('/') {
        return resolve_relative_url(base, redirect);
    }
    if redirect.starts_with('?') {
        let base_no_query = base.split('?').next().unwrap_or(base);
        let mut result = String::from(base_no_query);
        result.push_str(redirect);
        return result;
    }
    resolve_relative_url(base, redirect)
}
