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

#[inline]
pub fn is_hidden(path: &str) -> bool {
    if let Some(name) = get_filename(path) {
        name.starts_with('.')
    } else {
        false
    }
}

#[inline]
pub fn get_filename(path: &str) -> Option<&str> {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    match trimmed.rfind('/') {
        Some(pos) => Some(&trimmed[pos + 1..]),
        None => Some(trimmed),
    }
}

#[inline]
pub fn get_extension(path: &str) -> Option<&str> {
    let name = get_filename(path)?;
    if name.starts_with('.') && !name[1..].contains('.') {
        return None;
    }
    match name.rfind('.') {
        Some(pos) if pos > 0 => Some(&name[pos + 1..]),
        _ => None,
    }
}
