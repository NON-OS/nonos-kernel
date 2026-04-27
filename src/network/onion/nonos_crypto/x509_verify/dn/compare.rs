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

use super::rdn::rdn_equal;
use super::tlv::{read_tlv, unwrap_sequence};

pub(crate) fn dn_equal(a: &[u8], b: &[u8]) -> bool {
    if a.is_empty() || b.is_empty() {
        return false;
    }
    if a == b {
        return true;
    }
    dn_equal_normalized(a, b)
}

fn dn_equal_normalized(a: &[u8], b: &[u8]) -> bool {
    let a_inner = match unwrap_sequence(a) {
        Some(v) => v,
        None => return false,
    };
    let b_inner = match unwrap_sequence(b) {
        Some(v) => v,
        None => return false,
    };
    let (mut ai, mut bi) = (0usize, 0usize);
    while ai < a_inner.len() && bi < b_inner.len() {
        let (a_rdn, a_next) = match read_tlv(a_inner, ai) {
            Some(v) => v,
            None => return false,
        };
        let (b_rdn, b_next) = match read_tlv(b_inner, bi) {
            Some(v) => v,
            None => return false,
        };
        if !rdn_equal(a_rdn, b_rdn) {
            return false;
        }
        ai = a_next;
        bi = b_next;
    }
    ai >= a_inner.len() && bi >= b_inner.len()
}
