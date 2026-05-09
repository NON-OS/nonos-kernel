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

use crate::algs::AlgId;
use crate::error::SignError;
use crate::verify::cursor::Cursor;
use crate::verify::decoded::{DecodedEndpoint, DecodedManifest, DecodedPubSig};
use crate::wire::constants::SCHEMA_CAPSULE_MANIFEST;

pub fn decode_manifest(bytes: &[u8]) -> Result<DecodedManifest, SignError> {
    let mut c = Cursor::new(bytes);
    if c.u16_be()? != SCHEMA_CAPSULE_MANIFEST {
        return Err(SignError::KeyFileShape("manifest schema_version mismatch".into()));
    }
    let nonos_id_cert_id = c.array::<32>()?;
    let nlen = c.u8()? as usize;
    let nb = c.take(nlen)?;
    let namespace = String::from_utf8(nb.to_vec())
        .map_err(|_| SignError::KeyFileShape("manifest namespace utf8".into()))?;
    let version_major = c.u32_be()?;
    let _minor = c.u32_be()?;
    let _patch = c.u32_be()?;
    let tlen = c.u8()? as usize;
    let tb = c.take(tlen)?;
    let target_triple = String::from_utf8(tb.to_vec())
        .map_err(|_| SignError::KeyFileShape("manifest target utf8".into()))?;
    let payload_hash = c.array::<32>()?;
    let required_caps = c.u64_be()?;
    let optional_caps = c.u64_be()?;
    let ep_count = c.u8()? as usize;
    let mut endpoints: Vec<DecodedEndpoint> = Vec::with_capacity(ep_count);
    for _ in 0..ep_count {
        let kind = c.u8()?;
        let port = c.u32_be()?;
        let nm_len = c.u8()? as usize;
        let nm = c.take(nm_len)?;
        let name = String::from_utf8(nm.to_vec())
            .map_err(|_| SignError::KeyFileShape("manifest endpoint utf8".into()))?;
        endpoints.push(DecodedEndpoint { kind, port, name });
    }
    let signed_region_len = c.pos;
    let sig_count = c.u8()? as usize;
    let mut publisher_signatures: Vec<DecodedPubSig> = Vec::with_capacity(sig_count);
    for _ in 0..sig_count {
        let alg = AlgId::from_u8(c.u8()?)?;
        let key_id = c.array::<16>()?;
        let slen = c.u16_be()? as usize;
        let sig = c.take(slen)?.to_vec();
        publisher_signatures.push(DecodedPubSig { alg, key_id, sig });
    }
    if !c.at_end() {
        return Err(SignError::KeyFileShape("manifest trailing bytes".into()));
    }
    Ok(DecodedManifest {
        nonos_id_cert_id,
        namespace,
        version_major,
        target_triple,
        payload_hash,
        required_caps,
        optional_caps,
        endpoints,
        publisher_signatures,
        signed_region_len,
    })
}
