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

use super::types::*;

pub fn parse_xattr_name(name: &str) -> Result<(u8, &str), i32> {
    if let Some(n) = name.strip_prefix("user.") {
        return Ok((EXT4_XATTR_INDEX_USER, n));
    }
    if let Some(n) = name.strip_prefix("trusted.") {
        return Ok((EXT4_XATTR_INDEX_TRUSTED, n));
    }
    if let Some(n) = name.strip_prefix("security.") {
        return Ok((EXT4_XATTR_INDEX_SECURITY, n));
    }
    if let Some(n) = name.strip_prefix("system.") {
        return Ok((EXT4_XATTR_INDEX_SYSTEM, n));
    }
    Err(-95)
}
