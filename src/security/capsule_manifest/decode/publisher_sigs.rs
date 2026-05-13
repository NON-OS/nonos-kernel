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

use crate::crypto::asymmetric::alg_id::{sig_len, AlgId, MAX_SIG_BYTES};

use super::super::cursor::Cursor;
use super::super::error::ManifestDecodeError;
use super::super::schema::{PublisherSignature, MAX_PUBLISHER_SIGNATURES, PUBLISHER_KEY_ID_LEN};

pub(super) fn decode(c: &mut Cursor<'_>) -> Result<Vec<PublisherSignature>, ManifestDecodeError> {
    let count = c.u8()? as usize;
    if count == 0 || count > MAX_PUBLISHER_SIGNATURES {
        return Err(ManifestDecodeError::PublisherSignatureCount);
    }
    let mut sigs: Vec<PublisherSignature> = Vec::with_capacity(count);
    for _ in 0..count {
        let alg = AlgId::from_u8(c.u8()?)?;
        let key_id = c.array::<PUBLISHER_KEY_ID_LEN>()?;
        let slen = c.u16_be()? as usize;
        let expected = sig_len(alg);
        if slen != expected {
            return Err(ManifestDecodeError::SigLen { expected, got: slen });
        }
        let sbytes = c.take(slen)?;
        let mut sig = [0u8; MAX_SIG_BYTES];
        sig[..slen].copy_from_slice(sbytes);
        sigs.push(PublisherSignature { algorithm: alg, key_id, sig, sig_len: slen as u16 });
    }
    Ok(sigs)
}
