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
use crate::verify::decoded::{DecodedCert, DecodedPubKey, DecodedTaSig};
use crate::wire::constants::SCHEMA_NONOS_ID_CERT;

pub fn decode_cert(bytes: &[u8]) -> Result<DecodedCert, SignError> {
    let mut c = Cursor::new(bytes);
    if c.u16_be()? != SCHEMA_NONOS_ID_CERT {
        return Err(SignError::KeyFileShape("cert schema_version mismatch".into()));
    }
    let cert_serial = c.u64_be()?;
    let nonos_id = c.array::<32>()?;
    let glob_count = c.u8()? as usize;
    let mut namespace_globs: Vec<String> = Vec::with_capacity(glob_count);
    for _ in 0..glob_count {
        let glen = c.u8()? as usize;
        let gb = c.take(glen)?;
        namespace_globs.push(String::from_utf8(gb.to_vec()).map_err(|_| SignError::KeyFileShape("cert glob utf8".into()))?);
    }
    let allowed_caps_ceiling = c.u64_be()?;
    let mlen = c.u8()? as usize;
    let _meta = c.take(mlen)?;
    let valid_from_ms = c.u64_be()?;
    let valid_until_ms = c.u64_be()?;
    let trust_anchor_epoch = c.u64_be()?;
    let pk_count = c.u8()? as usize;
    let mut publisher_keys: Vec<DecodedPubKey> = Vec::with_capacity(pk_count);
    for _ in 0..pk_count {
        let alg = AlgId::from_u8(c.u8()?)?;
        let key_id = c.array::<16>()?;
        let plen = c.u16_be()? as usize;
        let pubkey = c.take(plen)?.to_vec();
        publisher_keys.push(DecodedPubKey { alg, key_id, pubkey });
    }
    let signed_region_len = c.pos;
    let sig_count = c.u8()? as usize;
    let mut trust_anchor_signatures: Vec<DecodedTaSig> = Vec::with_capacity(sig_count);
    for _ in 0..sig_count {
        let alg = AlgId::from_u8(c.u8()?)?;
        let slen = c.u16_be()? as usize;
        let sig = c.take(slen)?.to_vec();
        trust_anchor_signatures.push(DecodedTaSig { alg, sig });
    }
    if !c.at_end() {
        return Err(SignError::KeyFileShape("cert trailing bytes".into()));
    }
    Ok(DecodedCert {
        cert_serial,
        nonos_id,
        namespace_globs,
        allowed_caps_ceiling,
        valid_from_ms,
        valid_until_ms,
        trust_anchor_epoch,
        publisher_keys,
        trust_anchor_signatures,
        signed_region_len,
    })
}
