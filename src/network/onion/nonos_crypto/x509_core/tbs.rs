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
    if parser.peek_tag() == Some(0xA0) {
        parser.skip_structure()?;
    }
    parser.skip_structure()?;
    parser.skip_structure()?;
    let issuer_start = parser.offset;
    parser.skip_structure()?;
    let issuer_end = parser.offset;
    let issuer_der = parser.data[issuer_start..issuer_end].to_vec();
    let (not_before_ms, not_after_ms) = parse_validity(parser)?;
    let subject_start = parser.offset;
    parser.skip_structure()?;
    let subject_end = parser.offset;
    let subject_der = parser.data[subject_start..subject_end].to_vec();
    Ok((not_before_ms, not_after_ms, issuer_der, subject_der))
}

