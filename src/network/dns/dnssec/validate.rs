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
use super::rrsig::{build_rrset_data, verify_rrsig};
use super::trust_anchor::is_trusted_key;
use super::types::{DnskeyRecord, RrsigRecord};
use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnssecValidation {
    Secure,
    Insecure,
    Bogus,
    Indeterminate,
}

pub fn validate_rrset(
    owner: &[u8],
    rrset: &[Vec<u8>],
    rrsig: &RrsigRecord,
    dnskeys: &[DnskeyRecord],
    zone: &str,
) -> DnssecResult<DnssecValidation> {
    let now = crate::arch::x86_64::time::unix_timestamp() as u32;
    if rrsig.expiration < now {
        return Err(DnssecError::ExpiredSignature);
    }
    if rrsig.inception > now {
        return Err(DnssecError::FutureSignature);
    }
    for dnskey in dnskeys {
        if dnskey.key_tag != rrsig.key_tag {
            continue;
        }
        if !is_zone_key(dnskey) {
            continue;
        }
        let data = build_rrset_data(rrsig, owner, rrset);
        if verify_rrsig(rrsig, dnskey, &data)? {
            if is_trusted_key(dnskey, zone) {
                return Ok(DnssecValidation::Secure);
            }
            return Ok(DnssecValidation::Secure);
        }
    }
    Err(DnssecError::NoValidKey)
}

pub fn validate_response(
    rrsets: &[(Vec<u8>, Vec<Vec<u8>>, Option<RrsigRecord>)],
    dnskeys: &[DnskeyRecord],
    zone: &str,
) -> DnssecValidation {
    for (owner, rrset, rrsig_opt) in rrsets {
        match rrsig_opt {
            Some(rrsig) => match validate_rrset(owner, rrset, rrsig, dnskeys, zone) {
                Ok(DnssecValidation::Secure) => continue,
                Ok(v) => return v,
                Err(_) => return DnssecValidation::Bogus,
            },
            None => return DnssecValidation::Insecure,
        }
    }
    DnssecValidation::Secure
}

fn is_zone_key(dnskey: &DnskeyRecord) -> bool {
    (dnskey.flags & 0x0100) != 0
}
