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
use super::types::DnskeyRecord;
use alloc::vec::Vec;

pub(super) const ROOT_KSK_20170_KEY_TAG: u16 = 20326;
pub(super) const ROOT_KSK_20170_ALGORITHM: u8 = 8;

pub(super) static ROOT_KSK_20170_DS: [u8; 34] = [
    0x4F, 0x66, 0x00, 0x08, 0x02, 0xE4, 0x7A, 0x56, 0xDF, 0xA7, 0x22, 0xF6, 0x5B, 0x9A, 0x4E, 0x03,
    0x9B, 0x8C, 0xB9, 0x2F, 0x43, 0x29, 0x4B, 0x0F, 0xB9, 0x5B, 0x05, 0x57, 0x95, 0xC2, 0x35, 0x59,
    0x13, 0x24,
];

pub fn get_root_trust_anchors() -> Vec<(u16, u8, Vec<u8>)> {
    let mut anchors = Vec::new();
    anchors.push((ROOT_KSK_20170_KEY_TAG, ROOT_KSK_20170_ALGORITHM, ROOT_KSK_20170_DS.to_vec()));
    anchors
}

pub fn is_trusted_key(dnskey: &DnskeyRecord, zone: &str) -> bool {
    if zone != "." {
        return false;
    }
    let anchors = get_root_trust_anchors();
    for (key_tag, algorithm, _ds) in anchors {
        if dnskey.key_tag == key_tag && dnskey.algorithm as u8 == algorithm {
            return true;
        }
    }
    false
}

pub fn verify_ds_chain(parent_dnskey: &DnskeyRecord, child_ds: &[u8], child_zone: &[u8]) -> bool {
    if let Ok(computed) =
        super::keys::compute_ds_digest(child_zone, &encode_dnskey(parent_dnskey), 2)
    {
        return computed == child_ds;
    }
    false
}

fn encode_dnskey(dnskey: &DnskeyRecord) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&dnskey.flags.to_be_bytes());
    data.push(dnskey.protocol);
    data.push(dnskey.algorithm as u8);
    data.extend_from_slice(&dnskey.public_key);
    data
}
