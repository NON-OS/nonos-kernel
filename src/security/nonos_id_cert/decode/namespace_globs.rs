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

use alloc::vec::Vec;

use super::super::cursor::Cursor;
use super::super::error::IdCertDecodeError;
use super::super::schema::{NamespaceGlob, MAX_NAMESPACE_GLOBS, MAX_NAMESPACE_GLOB_LEN};

pub(super) fn decode(c: &mut Cursor<'_>) -> Result<Vec<NamespaceGlob>, IdCertDecodeError> {
    let count = c.u8()? as usize;
    if count == 0 || count > MAX_NAMESPACE_GLOBS {
        return Err(IdCertDecodeError::NamespaceGlobCount);
    }
    let mut globs: Vec<NamespaceGlob> = Vec::with_capacity(count);
    for _ in 0..count {
        let glen = c.u8()? as usize;
        if glen == 0 || glen > MAX_NAMESPACE_GLOB_LEN {
            return Err(IdCertDecodeError::NamespaceGlobLen);
        }
        let gbytes = c.take(glen)?;
        if core::str::from_utf8(gbytes).is_err() {
            return Err(IdCertDecodeError::NamespaceGlobNotUtf8);
        }
        let mut bytes = [0u8; MAX_NAMESPACE_GLOB_LEN];
        bytes[..glen].copy_from_slice(gbytes);
        globs.push(NamespaceGlob { bytes, len: glen as u8 });
    }
    Ok(globs)
}
