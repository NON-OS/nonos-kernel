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
use super::super::error::IdCertDecodeError;
use super::super::schema::{TrustAnchorSignature, MAX_TRUST_ANCHOR_SIGNATURES};

pub(super) fn decode(c: &mut Cursor<'_>) -> Result<Vec<TrustAnchorSignature>, IdCertDecodeError> {
    let count = c.u8()? as usize;
    if count == 0 || count > MAX_TRUST_ANCHOR_SIGNATURES {
        return Err(IdCertDecodeError::TrustAnchorSignatureCount);
    }
    let mut sigs: Vec<TrustAnchorSignature> = Vec::with_capacity(count);
    for _ in 0..count {
        let alg = AlgId::from_u8(c.u8()?)?;
        let slen = c.u16_be()? as usize;
        let expected = sig_len(alg);
        if slen != expected {
            return Err(IdCertDecodeError::SigLen { expected, got: slen });
        }
        let sbytes = c.take(slen)?;
        let mut sig = [0u8; MAX_SIG_BYTES];
        sig[..slen].copy_from_slice(sbytes);
        sigs.push(TrustAnchorSignature { algorithm: alg, sig, sig_len: slen as u16 });
    }
    Ok(sigs)
}
