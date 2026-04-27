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

use super::normalize::printable_string_equal;
use super::tlv::{read_tlv, read_tlv_raw};

pub(super) fn rdn_equal(a: &[u8], b: &[u8]) -> bool {
    let (mut ai, mut bi) = (0usize, 0usize);
    while ai < a.len() && bi < b.len() {
        let (a_atv, a_next) = match read_tlv(a, ai) {
            Some(v) => v,
            None => return false,
        };
        let (b_atv, b_next) = match read_tlv(b, bi) {
            Some(v) => v,
            None => return false,
        };
        if !atv_equal(a_atv, b_atv) {
            return false;
        }
        ai = a_next;
        bi = b_next;
    }
    ai >= a.len() && bi >= b.len()
}

fn atv_equal(a: &[u8], b: &[u8]) -> bool {
    let (a_oid, a_after_oid) = match read_tlv(a, 0) {
        Some(v) => v,
        None => return false,
    };
    let (b_oid, b_after_oid) = match read_tlv(b, 0) {
        Some(v) => v,
        None => return false,
    };
    if a_oid != b_oid {
        return false;
    }
    let a_tag = match a.get(a_after_oid) {
        Some(&t) => t,
        None => return false,
    };
    let b_tag = match b.get(b_after_oid) {
        Some(&t) => t,
        None => return false,
    };
    let (a_val, _) = match read_tlv_raw(a, a_after_oid) {
        Some(v) => v,
        None => return false,
    };
    let (b_val, _) = match read_tlv_raw(b, b_after_oid) {
        Some(v) => v,
        None => return false,
    };
    if a_tag == 0x13 && b_tag == 0x13 {
        return printable_string_equal(a_val, b_val);
    }
    a[a_after_oid..] == b[b_after_oid..]
}
