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

use super::super::cursor::Cursor;
use super::super::error::ManifestDecodeError;
use super::super::schema::{
    Version, MANIFEST_SCHEMA_VERSION, MAX_NAMESPACE_LEN, MAX_TARGET_TRIPLE_LEN,
    NONOS_ID_CERT_ID_LEN, PAYLOAD_HASH_LEN,
};

pub(super) struct Header {
    pub nonos_id_cert_id: [u8; NONOS_ID_CERT_ID_LEN],
    pub namespace: [u8; MAX_NAMESPACE_LEN],
    pub namespace_len: u8,
    pub version: Version,
    pub target_triple: [u8; MAX_TARGET_TRIPLE_LEN],
    pub target_triple_len: u8,
    pub payload_hash: [u8; PAYLOAD_HASH_LEN],
    pub required_caps: u64,
    pub optional_caps: u64,
}

pub(super) fn decode(c: &mut Cursor<'_>) -> Result<Header, ManifestDecodeError> {
    if c.u16_be()? != MANIFEST_SCHEMA_VERSION {
        return Err(ManifestDecodeError::SchemaVersion);
    }
    let nonos_id_cert_id = c.array::<NONOS_ID_CERT_ID_LEN>()?;
    let (namespace, namespace_len) = decode_namespace(c)?;
    let version = Version { major: c.u32_be()?, minor: c.u32_be()?, patch: c.u32_be()? };
    let (target_triple, target_triple_len) = decode_target_triple(c)?;
    let payload_hash = c.array::<PAYLOAD_HASH_LEN>()?;
    let required_caps = c.u64_be()?;
    let optional_caps = c.u64_be()?;
    if required_caps & optional_caps != 0 {
        return Err(ManifestDecodeError::OverlappingCaps);
    }
    Ok(Header {
        nonos_id_cert_id,
        namespace,
        namespace_len,
        version,
        target_triple,
        target_triple_len,
        payload_hash,
        required_caps,
        optional_caps,
    })
}

fn decode_namespace(c: &mut Cursor<'_>) -> Result<([u8; MAX_NAMESPACE_LEN], u8), ManifestDecodeError> {
    let n = c.u8()? as usize;
    if n == 0 || n > MAX_NAMESPACE_LEN {
        return Err(ManifestDecodeError::NamespaceLen);
    }
    let bytes = c.take(n)?;
    if core::str::from_utf8(bytes).is_err() {
        return Err(ManifestDecodeError::NamespaceNotUtf8);
    }
    let mut out = [0u8; MAX_NAMESPACE_LEN];
    out[..n].copy_from_slice(bytes);
    Ok((out, n as u8))
}

fn decode_target_triple(
    c: &mut Cursor<'_>,
) -> Result<([u8; MAX_TARGET_TRIPLE_LEN], u8), ManifestDecodeError> {
    let n = c.u8()? as usize;
    if n == 0 || n > MAX_TARGET_TRIPLE_LEN {
        return Err(ManifestDecodeError::TargetTripleLen);
    }
    let bytes = c.take(n)?;
    if core::str::from_utf8(bytes).is_err() {
        return Err(ManifestDecodeError::TargetTripleNotUtf8);
    }
    let mut out = [0u8; MAX_TARGET_TRIPLE_LEN];
    out[..n].copy_from_slice(bytes);
    Ok((out, n as u8))
}
