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

use alloc::string::String;

use super::visits::host_of;

/// What names the site at `url`: its host, or the whole address for one
/// with no host, such as `about:nonos`.
pub fn site(url: &str) -> String {
    let host = if url.contains("://") { host_of(url) } else { String::new() };
    if host.is_empty() {
        String::from(url.trim())
    } else {
        host
    }
}

/// What a page is called: its title, or the site it came from when the
/// title is blank. Empty only when both are.
pub fn title(title: &str, url: &str) -> String {
    match title.trim().is_empty() {
        true => site(url),
        false => String::from(title),
    }
}
