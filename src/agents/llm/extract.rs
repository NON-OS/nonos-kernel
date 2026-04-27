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

pub(super) fn extract_path(query: &str) -> Option<&str> {
    if let Some(idx) = query.find('/') {
        let end = query[idx..].find(' ').map(|e| idx + e).unwrap_or(query.len());
        return Some(&query[idx..end]);
    }
    None
}

pub(super) fn extract_command(query: &str) -> Option<&str> {
    for prefix in ["run ", "execute ", "shell "] {
        if let Some(idx) = query.find(prefix) {
            let start = idx + prefix.len();
            let cmd = query[start..].trim();
            if !cmd.is_empty() {
                return Some(cmd);
            }
        }
    }
    if query.contains('`') {
        let start = query.find('`')? + 1;
        let end = query[start..].find('`')? + start;
        return Some(&query[start..end]);
    }
    None
}

pub(super) fn extract_write_params(query: &str) -> Option<(&str, &str)> {
    let path = extract_path(query)?;
    if let Some(content_start) = query.find("content ") {
        let content = query[content_start + 8..].trim();
        return Some((path, content));
    }
    if let Some(quote_start) = query.find('"') {
        let start = quote_start + 1;
        if let Some(quote_end) = query[start..].find('"') {
            return Some((path, &query[start..start + quote_end]));
        }
    }
    None
}
