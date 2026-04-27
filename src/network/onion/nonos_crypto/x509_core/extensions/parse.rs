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

use super::basic_constraints::parse_basic_constraints;
use super::identifiers::{parse_authority_key_id, parse_octet_string_value};
use super::key_usage::{parse_ext_key_usage, parse_key_usage};
use super::oids::*;
use super::san::parse_san;
use crate::network::onion::nonos_crypto::types::X509Extensions;
use crate::network::onion::nonos_crypto::x509_der::DerParser;
use crate::network::onion::OnionError;

pub(crate) fn parse_extensions(
    parser: &mut DerParser,
    tbs_end: usize,
) -> Result<X509Extensions, OnionError> {
    let mut exts = X509Extensions::default();
    if parser.offset >= tbs_end || parser.peek_tag() != Some(0xA3) {
        return Ok(exts);
    }
    parser.expect_tag(0xA3)?;
    let _ctx_len = parser.read_length()?;
    parser.expect_sequence()?;
    let seq_len = parser.read_length()?;
    let seq_end = parser.offset + seq_len;
    while parser.offset < seq_end {
        parse_single_extension(parser, &mut exts)?;
    }
    Ok(exts)
}

fn parse_single_extension(
    parser: &mut DerParser,
    exts: &mut X509Extensions,
) -> Result<(), OnionError> {
    parser.expect_sequence()?;
    let ext_len = parser.read_length()?;
    let ext_end = parser.offset + ext_len;
    parser.expect_tag(0x06)?;
    let oid_len = parser.read_length()?;
    let oid_bytes = parser.read_bytes(oid_len)?;
    if parser.offset < ext_end && parser.peek_tag() == Some(0x01) {
        parser.expect_tag(0x01)?;
        let bool_len = parser.read_length()?;
        parser.skip(bool_len)?;
    }
    parser.expect_tag(0x04)?;
    let val_len = parser.read_length()?;
    let val_start = parser.offset;
    let val_end = val_start + val_len;
    if oid_bytes == OID_BASIC_CONSTRAINTS {
        parse_basic_constraints(&parser.data[val_start..val_end], &mut exts.basic_constraints)?;
    } else if oid_bytes == OID_KEY_USAGE {
        exts.key_usage = parse_key_usage(&parser.data[val_start..val_end])?;
    } else if oid_bytes == OID_EXT_KEY_USAGE {
        parse_ext_key_usage(&parser.data[val_start..val_end], &mut exts.ext_key_usage)?;
    } else if oid_bytes == OID_SUBJECT_KEY_ID {
        exts.subject_key_id = Some(parse_octet_string_value(&parser.data[val_start..val_end])?);
    } else if oid_bytes == OID_AUTHORITY_KEY_ID {
        exts.authority_key_id = parse_authority_key_id(&parser.data[val_start..val_end])?;
    } else if oid_bytes == OID_SUBJECT_ALT_NAME {
        parse_san(&parser.data[val_start..val_end], &mut exts.san_dns_names)?;
    }
    parser.offset = ext_end;
    Ok(())
}
