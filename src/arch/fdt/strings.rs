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

use super::error::FdtError;

// Resolve a NUL-terminated string at `offset` inside the strings block.
// Returns the bytes without the terminator.
pub fn resolve(strings: &[u8], offset: u32) -> Result<&[u8], FdtError> {
    let start = offset as usize;
    if start >= strings.len() {
        return Err(FdtError::StringMissing);
    }
    let mut end = start;
    while end < strings.len() && strings[end] != 0 {
        end += 1;
    }
    if end == strings.len() {
        return Err(FdtError::StringMissing);
    }
    Ok(&strings[start..end])
}
