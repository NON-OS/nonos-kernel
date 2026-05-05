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

use super::schema::{
    EndpointDecl, Manifest, ManifestError, Version, MANIFEST_SCHEMA_VERSION, MAX_ENDPOINTS,
    MAX_ENDPOINT_NAME_LEN, MAX_NAMESPACE_LEN,
};

// Wire layout, big-endian:
//
//   u16  schema_version
//   [32] publisher_pubkey
//   u8   namespace_len
//   [n]  namespace                 (n <= MAX_NAMESPACE_LEN)
//   u32  version.major
//   u32  version.minor
//   u32  version.patch
//   [32] package_hash
//   [32] entry_hash
//   u64  required_caps
//   u64  optional_caps
//   u8   endpoint_count            (<= MAX_ENDPOINTS)
//   for each endpoint:
//     u8  name_len                 (<= MAX_ENDPOINT_NAME_LEN)
//     [n] name                     (UTF-8)
//   [64] signature
//
// Total length is exact; trailing bytes are an error.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    UnexpectedEof,
    TrailingBytes,
    Schema(ManifestError),
}

impl From<ManifestError> for DecodeError {
    fn from(e: ManifestError) -> Self {
        DecodeError::Schema(e)
    }
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if self.pos + n > self.buf.len() {
            return Err(DecodeError::UnexpectedEof);
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }

    fn u16_be(&mut self) -> Result<u16, DecodeError> {
        let s = self.take(2)?;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }

    fn u32_be(&mut self) -> Result<u32, DecodeError> {
        let s = self.take(4)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }

    fn u64_be(&mut self) -> Result<u64, DecodeError> {
        let s = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(s);
        Ok(u64::from_be_bytes(a))
    }

    fn array32(&mut self) -> Result<[u8; 32], DecodeError> {
        let s = self.take(32)?;
        let mut a = [0u8; 32];
        a.copy_from_slice(s);
        Ok(a)
    }

    fn array64(&mut self) -> Result<[u8; 64], DecodeError> {
        let s = self.take(64)?;
        let mut a = [0u8; 64];
        a.copy_from_slice(s);
        Ok(a)
    }
}

pub fn decode(bytes: &[u8]) -> Result<Manifest, DecodeError> {
    let mut c = Cursor::new(bytes);

    let schema_version = c.u16_be()?;
    if schema_version != MANIFEST_SCHEMA_VERSION {
        return Err(ManifestError::SchemaVersion.into());
    }

    let publisher_pubkey = c.array32()?;

    let ns_len = c.u8()? as usize;
    if ns_len > MAX_NAMESPACE_LEN {
        return Err(ManifestError::NamespaceTooLong.into());
    }
    let mut app_namespace = [0u8; MAX_NAMESPACE_LEN];
    let ns_bytes = c.take(ns_len)?;
    app_namespace[..ns_len].copy_from_slice(ns_bytes);

    let version = Version { major: c.u32_be()?, minor: c.u32_be()?, patch: c.u32_be()? };

    let package_hash = c.array32()?;
    let entry_hash = c.array32()?;
    let required_caps = c.u64_be()?;
    let optional_caps = c.u64_be()?;
    if required_caps & optional_caps != 0 {
        return Err(ManifestError::OverlappingCaps.into());
    }

    let endpoint_count = c.u8()? as usize;
    if endpoint_count > MAX_ENDPOINTS {
        return Err(ManifestError::TooManyEndpoints.into());
    }
    let mut endpoints: Vec<EndpointDecl> = Vec::with_capacity(endpoint_count);
    for _ in 0..endpoint_count {
        let name_len = c.u8()? as usize;
        if name_len > MAX_ENDPOINT_NAME_LEN {
            return Err(ManifestError::EndpointNameTooLong.into());
        }
        let name_bytes = c.take(name_len)?;
        if core::str::from_utf8(name_bytes).is_err() {
            return Err(ManifestError::EndpointNameNotUtf8.into());
        }
        if endpoints
            .iter()
            .any(|e| e.name_len as usize == name_len && &e.name[..name_len] == name_bytes)
        {
            return Err(ManifestError::DuplicateEndpoint.into());
        }
        let mut name = [0u8; MAX_ENDPOINT_NAME_LEN];
        name[..name_len].copy_from_slice(name_bytes);
        endpoints.push(EndpointDecl { name, name_len: name_len as u8 });
    }

    let signature = c.array64()?;

    if c.pos != bytes.len() {
        return Err(DecodeError::TrailingBytes);
    }

    Ok(Manifest {
        schema_version,
        publisher_pubkey,
        app_namespace,
        app_namespace_len: ns_len as u8,
        version,
        package_hash,
        entry_hash,
        required_caps,
        optional_caps,
        endpoints,
        signature,
    })
}
