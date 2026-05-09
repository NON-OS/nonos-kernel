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
use super::super::error::ManifestDecodeError;
use super::super::schema::{
    EndpointDecl, EndpointKind, MAX_ENDPOINTS, MAX_ENDPOINT_NAME_LEN,
};

pub(super) fn decode(c: &mut Cursor<'_>) -> Result<Vec<EndpointDecl>, ManifestDecodeError> {
    let count = c.u8()? as usize;
    if count > MAX_ENDPOINTS {
        return Err(ManifestDecodeError::EndpointCount);
    }
    let mut endpoints: Vec<EndpointDecl> = Vec::with_capacity(count);
    for _ in 0..count {
        let kind_byte = c.u8()?;
        let kind = EndpointKind::from_u8(kind_byte)
            .ok_or(ManifestDecodeError::EndpointKind(kind_byte))?;
        let port = c.u32_be()?;
        let name_len = c.u8()? as usize;
        if name_len == 0 || name_len > MAX_ENDPOINT_NAME_LEN {
            return Err(ManifestDecodeError::EndpointNameLen);
        }
        let nbytes = c.take(name_len)?;
        if core::str::from_utf8(nbytes).is_err() {
            return Err(ManifestDecodeError::EndpointNameNotUtf8);
        }
        if endpoints.iter().any(|e| {
            e.kind == kind
                && e.name_len as usize == name_len
                && &e.name[..name_len] == nbytes
        }) {
            return Err(ManifestDecodeError::DuplicateEndpoint);
        }
        let mut name = [0u8; MAX_ENDPOINT_NAME_LEN];
        name[..name_len].copy_from_slice(nbytes);
        endpoints.push(EndpointDecl { kind, port, name, name_len: name_len as u8 });
    }
    Ok(endpoints)
}
