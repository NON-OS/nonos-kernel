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

//! Top-level index encoder. Writes the same byte order the decoder
//! reads. The signed bytes (everything before the trailing
//! signature) are returned alongside the full blob so a caller can
//! sign the exact range without re-encoding.

extern crate alloc;

use alloc::vec::Vec;

use super::encode_entry;
use super::writer::Writer;
use crate::types::MarketplaceIndex;

/// Result of encoding an index. `signed_bytes` is what the
/// signer must sign; `blob` is the full index including the
/// already-attached `index_signature` from the source struct.
/// A caller that wants to *produce* a signed blob should pass an
/// index with an empty `index_signature`, take the returned
/// `signed_bytes`, sign them, and append the signature length-
/// prefixed; helpers on top of this function do that round trip.
pub struct EncodedIndex {
    pub signed_bytes: Vec<u8>,
    pub blob: Vec<u8>,
}

pub fn encode_index(index: &MarketplaceIndex) -> EncodedIndex {
    let mut signed: Vec<u8> = Vec::new();
    {
        let mut w = Writer::new(&mut signed);
        w.u32(index.schema_version);
        w.lp_string(&index.operator_id);
        w.fixed(&index.operator_pubkey);
        w.u64(index.published_at_ms);
        w.u64(index.serial);
        w.u32(index.entries.len() as u32);
        for entry in &index.entries {
            encode_entry::write(&mut w, entry);
        }
    }

    let mut blob = signed.clone();
    {
        let mut w = Writer::new(&mut blob);
        w.lp_bytes(&index.index_signature);
    }

    EncodedIndex { signed_bytes: signed, blob }
}

/// Build a fully-signed blob from an index whose `index_signature`
/// is empty. The caller supplies a signing closure that consumes
/// the canonical signed-bytes range and returns the 64-byte
/// Ed25519 signature; the encoder appends it as the trailing
/// length-prefixed field. Returning the signature alongside the
/// blob lets a host-side tool persist both without re-running the
/// signer.
pub fn encode_and_sign<F>(
    mut index: MarketplaceIndex,
    sign: F,
) -> (Vec<u8>, [u8; 64])
where
    F: FnOnce(&[u8]) -> [u8; 64],
{
    index.index_signature.clear();
    let encoded = encode_index(&index);
    let signature = sign(&encoded.signed_bytes);

    let mut blob = encoded.signed_bytes;
    {
        let mut w = Writer::new(&mut blob);
        w.lp_bytes(&signature);
    }
    (blob, signature)
}
