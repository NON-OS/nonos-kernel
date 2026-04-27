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
use super::error::{DnssecError, DnssecResult};
use super::types::{DnskeyRecord, DnssecAlgorithm};
use alloc::vec::Vec;

pub fn parse_dnskey(data: &[u8]) -> DnssecResult<DnskeyRecord> {
    if data.len() < 4 {
        return Err(DnssecError::ParseError);
    }
    let flags = u16::from_be_bytes([data[0], data[1]]);
    let protocol = data[2];
    let algorithm = DnssecAlgorithm::from_u8(data[3]).ok_or(DnssecError::UnknownAlgorithm)?;
    let public_key = data[4..].to_vec();
    let key_tag = compute_key_tag(data);
    Ok(DnskeyRecord { flags, protocol, algorithm, public_key, key_tag })
}

pub fn compute_key_tag(rdata: &[u8]) -> u16 {
    let mut ac: u32 = 0;
    for (i, &byte) in rdata.iter().enumerate() {
        if i & 1 == 0 {
            ac += (byte as u32) << 8;
        } else {
            ac += byte as u32;
        }
    }
    ac += (ac >> 16) & 0xFFFF;
    (ac & 0xFFFF) as u16
}

pub fn compute_ds_digest(
    owner: &[u8],
    dnskey_rdata: &[u8],
    digest_type: u8,
) -> DnssecResult<Vec<u8>> {
    let mut input = owner.to_vec();
    input.extend_from_slice(dnskey_rdata);
    match digest_type {
        1 => Err(DnssecError::UnsupportedAlgorithm),
        2 => Ok(crate::crypto::hash::sha256::sha256(&input).to_vec()),
        4 => Ok(crate::crypto::hash::sha384::sha384(&input).to_vec()),
        _ => Err(DnssecError::UnsupportedAlgorithm),
    }
}
