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

use alloc::vec::Vec;
use crate::network::onion::OnionError;
use super::super::x509_der::DerParser;
use super::super::x509_time::parse_validity;

pub(super) fn parse_tbs_fields(parser: &mut DerParser) -> Result<(u64, u64, Vec<u8>, Vec<u8>), OnionError> {
    crate::sys::serial::print(b"[X509] tbs offset=");
    crate::sys::serial::print_dec(parser.offset as u64);
    crate::sys::serial::print(b" tag=0x");
    if let Some(t) = parser.peek_tag() {
        crate::sys::serial::print_hex(t as u64);
    }
    crate::sys::serial::println(b"");
    if parser.peek_tag() == Some(0xA0) {
        crate::sys::serial::println(b"[X509] skipping version");
        parser.skip_structure()?;
    }
    crate::sys::serial::println(b"[X509] skipping serialNumber");
    parser.skip_structure()?;
    crate::sys::serial::println(b"[X509] skipping signature");
    parser.skip_structure()?;
    crate::sys::serial::println(b"[X509] reading issuer");
    let issuer_start = parser.offset;
    parser.skip_structure()?;
    let issuer_end = parser.offset;
    let issuer_der = parser.data[issuer_start..issuer_end].to_vec();
    crate::sys::serial::println(b"[X509] parsing validity");
    let (not_before_ms, not_after_ms) = parse_validity(parser)?;
    crate::sys::serial::println(b"[X509] reading subject");
    let subject_start = parser.offset;
    parser.skip_structure()?;
    let subject_end = parser.offset;
    let subject_der = parser.data[subject_start..subject_end].to_vec();
    crate::sys::serial::println(b"[X509] tbs_fields done");
    Ok((not_before_ms, not_after_ms, issuer_der, subject_der))
}

