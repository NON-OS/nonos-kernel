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

/// Where address bar text that is not an address is searched by default:
/// the query, form-encoded, replaces %s. The HTML endpoint serves results
/// without scripts, which is what this browser runs best.
pub const DEFAULT_SEARCH: &str = "https://html.duckduckgo.com/html/?q=%s";

const MAX_TEMPLATE: usize = 512;

/// The template searches go to: the custom one when set, else the default.
pub fn template(custom: Option<&str>) -> &str {
    custom.unwrap_or(DEFAULT_SEARCH)
}

/// `s` as a search template, trimmed, or why it cannot be one: it must be
/// an http or https address with %s where the words go, and no spaces.
pub fn check(s: &str) -> Result<String, &'static str> {
    let t = s.trim();
    let scheme = ["https://", "http://"]
        .iter()
        .any(|p| t.get(..p.len()).is_some_and(|h| h.eq_ignore_ascii_case(p)) && t.len() > p.len());
    match () {
        _ if !scheme => Err("A template starts with https:// or http://."),
        _ if !t.contains("%s") => Err("Put %s where the search words go."),
        _ if t.chars().any(|c| c.is_whitespace() || c.is_control()) => {
            Err("A template has no spaces.")
        }
        _ if t.len() > MAX_TEMPLATE => Err("That template is too long."),
        _ => Ok(String::from(t)),
    }
}
