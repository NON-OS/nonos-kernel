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

use crate::network::onion::OnionError;
use super::super::x509_der::DerParser;
use super::super::types::{
    X509Extensions, BasicConstraints, ExtKeyUsage,
};

// Well-known extension OIDs (encoded as DER OID content bytes)
// 2.5.29.19 — Basic Constraints
const OID_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1D, 0x13];
// 2.5.29.15 — Key Usage
const OID_KEY_USAGE: &[u8] = &[0x55, 0x1D, 0x0F];
// 2.5.29.37 — Extended Key Usage
const OID_EXT_KEY_USAGE: &[u8] = &[0x55, 0x1D, 0x25];
// 2.5.29.14 — Subject Key Identifier
const OID_SUBJECT_KEY_ID: &[u8] = &[0x55, 0x1D, 0x0E];
// 2.5.29.35 — Authority Key Identifier
const OID_AUTHORITY_KEY_ID: &[u8] = &[0x55, 0x1D, 0x23];

// EKU OID values (DER-encoded OID content bytes)
// 1.3.6.1.5.5.7.3.1 — id-kp-serverAuth
const OID_EKU_SERVER_AUTH: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
// 1.3.6.1.5.5.7.3.2 — id-kp-clientAuth
const OID_EKU_CLIENT_AUTH: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];
// 1.3.6.1.5.5.7.3.9 — id-kp-OCSPSigning
const OID_EKU_OCSP_SIGNING: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09];

/// Parse X.509v3 extensions from the `[3] EXPLICIT` context tag.
///
/// Called after subject + SPKI have been parsed. If no extensions tag is
/// present, returns default (empty) extensions — this is valid for v1 certs.
pub(super) fn parse_extensions(parser: &mut DerParser, tbs_end: usize) -> Result<X509Extensions, OnionError> {
    let mut exts = X509Extensions::default();

    // Extensions are wrapped in `[3] EXPLICIT { SEQUENCE { ... } }`
    if parser.offset >= tbs_end || parser.peek_tag() != Some(0xA3) {
        return Ok(exts);
    }

    // Enter [3] context tag
    parser.expect_tag(0xA3)?;
    let _ctx_len = parser.read_length()?;

    // Inner SEQUENCE of Extension values
    parser.expect_sequence()?;
    let seq_len = parser.read_length()?;
    let seq_end = parser.offset + seq_len;

    while parser.offset < seq_end {
        parse_single_extension(parser, &mut exts)?;
    }

    Ok(exts)
}

/// Parse one Extension ::= SEQUENCE { extnID OID, critical BOOL DEFAULT FALSE, extnValue OCTET STRING }
fn parse_single_extension(parser: &mut DerParser, exts: &mut X509Extensions) -> Result<(), OnionError> {
    parser.expect_sequence()?;
    let ext_len = parser.read_length()?;
    let ext_end = parser.offset + ext_len;

    // extnID — OID
    parser.expect_tag(0x06)?;
    let oid_len = parser.read_length()?;
    let oid_bytes = parser.read_bytes(oid_len)?;

    // critical — optional BOOLEAN (tag 0x01)
    if parser.offset < ext_end && parser.peek_tag() == Some(0x01) {
        parser.expect_tag(0x01)?;
        let bool_len = parser.read_length()?;
        parser.skip(bool_len)?;
    }

    // extnValue — OCTET STRING wrapping the extension content
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
    }
    // Unknown extensions: silently skip (non-critical ones are safe to ignore)

    parser.offset = ext_end;
    Ok(())
}

/// BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER OPTIONAL }
fn parse_basic_constraints(data: &[u8], bc: &mut BasicConstraints) -> Result<(), OnionError> {
    let mut p = DerParser::new(data);
    p.expect_sequence()?;
    let seq_len = p.read_length()?;
    let seq_end = p.offset + seq_len;

    // Empty sequence means cA=false, no pathLen
    if p.offset >= seq_end {
        return Ok(());
    }

    // cA — BOOLEAN (tag 0x01)
    if p.peek_tag() == Some(0x01) {
        p.expect_tag(0x01)?;
        let len = p.read_length()?;
        if len == 1 && p.offset < p.data.len() {
            bc.ca = p.data[p.offset] != 0;
            p.offset += 1;
        } else {
            p.skip(len)?;
        }
    }

    // pathLenConstraint — INTEGER (tag 0x02)
    if p.offset < seq_end && p.peek_tag() == Some(0x02) {
        p.expect_tag(0x02)?;
        let len = p.read_length()?;
        if len == 1 && p.offset < p.data.len() {
            bc.path_len_constraint = Some(p.data[p.offset]);
            p.offset += 1;
        } else {
            p.skip(len)?;
        }
    }

    Ok(())
}

/// KeyUsage ::= BIT STRING — returns the key usage bits as u16
fn parse_key_usage(data: &[u8]) -> Result<u16, OnionError> {
    let mut p = DerParser::new(data);
    p.expect_tag(0x03)?;
    let len = p.read_length()?;
    if len < 2 {
        return Ok(0);
    }
    let _unused_bits = p.data.get(p.offset).copied().unwrap_or(0);
    p.offset += 1;

    // First byte contains the primary key usage flags
    let byte0 = p.data.get(p.offset).copied().unwrap_or(0);
    let mut bits = byte0 as u16;

    // Optional second byte for extended bits
    if len > 2 {
        let byte1 = p.data.get(p.offset + 1).copied().unwrap_or(0);
        bits |= (byte1 as u16) << 8;
    }

    Ok(bits)
}

/// ExtKeyUsage ::= SEQUENCE OF OID
fn parse_ext_key_usage(data: &[u8], ekus: &mut alloc::vec::Vec<ExtKeyUsage>) -> Result<(), OnionError> {
    let mut p = DerParser::new(data);
    p.expect_sequence()?;
    let seq_len = p.read_length()?;
    let seq_end = p.offset + seq_len;

    while p.offset < seq_end {
        p.expect_tag(0x06)?;
        let oid_len = p.read_length()?;
        let oid_bytes = p.read_bytes(oid_len)?;
        if oid_bytes == OID_EKU_SERVER_AUTH {
            ekus.push(ExtKeyUsage::ServerAuth);
        } else if oid_bytes == OID_EKU_CLIENT_AUTH {
            ekus.push(ExtKeyUsage::ClientAuth);
        } else if oid_bytes == OID_EKU_OCSP_SIGNING {
            ekus.push(ExtKeyUsage::OcspSigning);
        }
        // Unknown EKU OIDs are silently skipped
    }

    Ok(())
}

/// Unwrap an OCTET STRING value from the extnValue content (for SKI)
fn parse_octet_string_value(data: &[u8]) -> Result<alloc::vec::Vec<u8>, OnionError> {
    let mut p = DerParser::new(data);
    p.expect_tag(0x04)?;
    let len = p.read_length()?;
    let bytes = p.read_bytes(len)?;
    Ok(bytes.to_vec())
}

/// AuthorityKeyIdentifier ::= SEQUENCE { keyIdentifier [0] IMPLICIT OCTET STRING OPTIONAL, ... }
fn parse_authority_key_id(data: &[u8]) -> Result<Option<alloc::vec::Vec<u8>>, OnionError> {
    let mut p = DerParser::new(data);
    p.expect_sequence()?;
    let seq_len = p.read_length()?;
    let seq_end = p.offset + seq_len;

    if p.offset >= seq_end {
        return Ok(None);
    }

    // keyIdentifier is [0] IMPLICIT — tag 0x80
    if p.peek_tag() == Some(0x80) {
        p.expect_tag(0x80)?;
        let len = p.read_length()?;
        let bytes = p.read_bytes(len)?;
        return Ok(Some(bytes.to_vec()));
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    // Helper: build a [3] EXPLICIT { SEQUENCE { ...extensions... } } wrapper
    fn wrap_extensions(inner_exts: &[u8]) -> alloc::vec::Vec<u8> {
        // inner_exts is the concatenation of Extension SEQUENCE values
        // Wrap in SEQUENCE
        let mut seq = vec![0x30]; // SEQUENCE tag
        push_der_length(&mut seq, inner_exts.len());
        seq.extend_from_slice(inner_exts);
        // Wrap in [3] context tag
        let mut ctx = vec![0xA3]; // context [3]
        push_der_length(&mut ctx, seq.len());
        ctx.extend_from_slice(&seq);
        ctx
    }

    // Helper: build a single Extension SEQUENCE { OID, [critical], OCTET STRING { value } }
    fn build_extension(oid: &[u8], critical: bool, value: &[u8]) -> alloc::vec::Vec<u8> {
        let mut inner = alloc::vec::Vec::new();
        // OID
        inner.push(0x06);
        push_der_length(&mut inner, oid.len());
        inner.extend_from_slice(oid);
        // critical BOOLEAN (only if true)
        if critical {
            inner.extend_from_slice(&[0x01, 0x01, 0xFF]);
        }
        // extnValue OCTET STRING
        inner.push(0x04);
        push_der_length(&mut inner, value.len());
        inner.extend_from_slice(value);
        // Wrap in SEQUENCE
        let mut ext = vec![0x30];
        push_der_length(&mut ext, inner.len());
        ext.extend_from_slice(&inner);
        ext
    }

    fn push_der_length(buf: &mut alloc::vec::Vec<u8>, len: usize) {
        if len < 128 {
            buf.push(len as u8);
        } else if len < 256 {
            buf.push(0x81);
            buf.push(len as u8);
        } else {
            buf.push(0x82);
            buf.push((len >> 8) as u8);
            buf.push(len as u8);
        }
    }

    // --- BasicConstraints tests ---

    #[test]
    fn test_parse_basic_constraints_ca_true() {
        // BasicConstraints ::= SEQUENCE { cA BOOLEAN TRUE }
        let bc_value = &[0x30, 0x03, 0x01, 0x01, 0xFF];
        let mut bc = BasicConstraints::default();
        parse_basic_constraints(bc_value, &mut bc).unwrap();
        assert!(bc.ca);
        assert_eq!(bc.path_len_constraint, None);
    }

    #[test]
    fn test_parse_basic_constraints_ca_false() {
        // BasicConstraints ::= SEQUENCE { cA BOOLEAN FALSE }
        let bc_value = &[0x30, 0x03, 0x01, 0x01, 0x00];
        let mut bc = BasicConstraints::default();
        parse_basic_constraints(bc_value, &mut bc).unwrap();
        assert!(!bc.ca);
    }

    #[test]
    fn test_parse_basic_constraints_ca_true_with_pathlen() {
        // BasicConstraints ::= SEQUENCE { cA BOOLEAN TRUE, pathLen INTEGER 2 }
        let bc_value = &[0x30, 0x06, 0x01, 0x01, 0xFF, 0x02, 0x01, 0x02];
        let mut bc = BasicConstraints::default();
        parse_basic_constraints(bc_value, &mut bc).unwrap();
        assert!(bc.ca);
        assert_eq!(bc.path_len_constraint, Some(2));
    }

    #[test]
    fn test_parse_basic_constraints_empty_sequence() {
        // BasicConstraints ::= SEQUENCE {} — means cA=false (DEFAULT)
        let bc_value = &[0x30, 0x00];
        let mut bc = BasicConstraints::default();
        parse_basic_constraints(bc_value, &mut bc).unwrap();
        assert!(!bc.ca);
        assert_eq!(bc.path_len_constraint, None);
    }

    #[test]
    fn test_parse_basic_constraints_pathlen_zero() {
        // BasicConstraints ::= SEQUENCE { cA TRUE, pathLen 0 }
        let bc_value = &[0x30, 0x06, 0x01, 0x01, 0xFF, 0x02, 0x01, 0x00];
        let mut bc = BasicConstraints::default();
        parse_basic_constraints(bc_value, &mut bc).unwrap();
        assert!(bc.ca);
        assert_eq!(bc.path_len_constraint, Some(0));
    }

    // --- Key Usage tests ---

    #[test]
    fn test_parse_key_usage_digital_signature() {
        // BIT STRING: 03 02 07 80 — 1 unused bit, byte = 0x80 → bit 7 = digitalSignature
        // But RFC 5280 encodes KU with MSB-first: bit 0 = digitalSignature = 0x80
        let ku_value = &[0x03, 0x02, 0x07, 0x80];
        let bits = parse_key_usage(ku_value).unwrap();
        assert_eq!(bits, 0x80);
    }

    #[test]
    fn test_parse_key_usage_cert_sign_and_crl_sign() {
        // BIT STRING: 03 02 01 06 — keyCertSign(5) | cRLSign(6) = 0x06
        let ku_value = &[0x03, 0x02, 0x01, 0x06];
        let bits = parse_key_usage(ku_value).unwrap();
        assert_eq!(bits, 0x06);
    }

    #[test]
    fn test_parse_key_usage_empty() {
        // BIT STRING with len < 2 returns 0
        let ku_value = &[0x03, 0x01, 0x00];
        let bits = parse_key_usage(ku_value).unwrap();
        assert_eq!(bits, 0);
    }

    #[test]
    fn test_parse_key_usage_two_bytes() {
        // BIT STRING: 03 03 00 A0 08 — two KU bytes
        let ku_value = &[0x03, 0x03, 0x00, 0xA0, 0x08];
        let bits = parse_key_usage(ku_value).unwrap();
        assert_eq!(bits, 0xA0 | (0x08 << 8));
    }

    // --- Extended Key Usage tests ---

    #[test]
    fn test_parse_eku_server_auth() {
        // EKU ::= SEQUENCE { OID serverAuth }
        let mut eku_inner = alloc::vec::Vec::new();
        eku_inner.push(0x06); // OID tag
        eku_inner.push(OID_EKU_SERVER_AUTH.len() as u8);
        eku_inner.extend_from_slice(OID_EKU_SERVER_AUTH);
        let mut eku_value = vec![0x30]; // SEQUENCE
        push_der_length(&mut eku_value, eku_inner.len());
        eku_value.extend_from_slice(&eku_inner);

        let mut ekus = alloc::vec::Vec::new();
        parse_ext_key_usage(&eku_value, &mut ekus).unwrap();
        assert_eq!(ekus, vec![ExtKeyUsage::ServerAuth]);
    }

    #[test]
    fn test_parse_eku_server_and_client_auth() {
        let mut eku_inner = alloc::vec::Vec::new();
        // serverAuth OID
        eku_inner.push(0x06);
        eku_inner.push(OID_EKU_SERVER_AUTH.len() as u8);
        eku_inner.extend_from_slice(OID_EKU_SERVER_AUTH);
        // clientAuth OID
        eku_inner.push(0x06);
        eku_inner.push(OID_EKU_CLIENT_AUTH.len() as u8);
        eku_inner.extend_from_slice(OID_EKU_CLIENT_AUTH);

        let mut eku_value = vec![0x30];
        push_der_length(&mut eku_value, eku_inner.len());
        eku_value.extend_from_slice(&eku_inner);

        let mut ekus = alloc::vec::Vec::new();
        parse_ext_key_usage(&eku_value, &mut ekus).unwrap();
        assert_eq!(ekus, vec![ExtKeyUsage::ServerAuth, ExtKeyUsage::ClientAuth]);
    }

    #[test]
    fn test_parse_eku_unknown_oid_skipped() {
        // An unknown EKU OID should be silently skipped
        let unknown_oid: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0xFF];
        let mut eku_inner = alloc::vec::Vec::new();
        eku_inner.push(0x06);
        eku_inner.push(unknown_oid.len() as u8);
        eku_inner.extend_from_slice(unknown_oid);

        let mut eku_value = vec![0x30];
        push_der_length(&mut eku_value, eku_inner.len());
        eku_value.extend_from_slice(&eku_inner);

        let mut ekus = alloc::vec::Vec::new();
        parse_ext_key_usage(&eku_value, &mut ekus).unwrap();
        assert!(ekus.is_empty());
    }

    // --- Subject Key Identifier tests ---

    #[test]
    fn test_parse_ski() {
        // OCTET STRING { OCTET STRING { 20 bytes } }
        let kid: [u8; 20] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
            0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14,
        ];
        let mut ski_value = vec![0x04, 0x14]; // OCTET STRING, length 20
        ski_value.extend_from_slice(&kid);

        let result = parse_octet_string_value(&ski_value).unwrap();
        assert_eq!(result, kid.to_vec());
    }

    // --- Authority Key Identifier tests ---

    #[test]
    fn test_parse_aki_with_key_id() {
        // AKI ::= SEQUENCE { [0] IMPLICIT OCTET STRING }
        let kid: [u8; 20] = [
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33,
            0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
        ];
        let mut aki_value = alloc::vec::Vec::new();
        // Inner: [0] IMPLICIT (tag 0x80)
        let mut inner = vec![0x80, 0x14]; // tag + length 20
        inner.extend_from_slice(&kid);
        // Wrap in SEQUENCE
        aki_value.push(0x30);
        push_der_length(&mut aki_value, inner.len());
        aki_value.extend_from_slice(&inner);

        let result = parse_authority_key_id(&aki_value).unwrap();
        assert_eq!(result, Some(kid.to_vec()));
    }

    #[test]
    fn test_parse_aki_empty_sequence() {
        let aki_value = &[0x30, 0x00]; // SEQUENCE {}
        let result = parse_authority_key_id(aki_value).unwrap();
        assert_eq!(result, None);
    }

    // --- Full parse_extensions integration tests ---

    #[test]
    fn test_parse_extensions_no_tag() {
        // No 0xA3 tag → returns default extensions
        let data = &[0x30, 0x00]; // some non-extension data
        let mut parser = DerParser::new(data);
        let exts = parse_extensions(&mut parser, data.len()).unwrap();
        assert!(!exts.basic_constraints.ca);
        assert_eq!(exts.key_usage, 0);
        assert!(exts.ext_key_usage.is_empty());
        assert!(exts.subject_key_id.is_none());
        assert!(exts.authority_key_id.is_none());
    }

    #[test]
    fn test_parse_extensions_at_tbs_end() {
        // Parser offset == tbs_end → returns default
        let data: &[u8] = &[];
        let mut parser = DerParser::new(data);
        let exts = parse_extensions(&mut parser, 0).unwrap();
        assert!(!exts.basic_constraints.ca);
    }

    #[test]
    fn test_parse_extensions_basic_constraints_ca() {
        // Build: BasicConstraints { cA: true, pathLen: 1 }
        let bc_value = &[0x30, 0x06, 0x01, 0x01, 0xFF, 0x02, 0x01, 0x01];
        let ext = build_extension(OID_BASIC_CONSTRAINTS, true, bc_value);
        let wrapped = wrap_extensions(&ext);

        let mut parser = DerParser::new(&wrapped);
        let exts = parse_extensions(&mut parser, wrapped.len()).unwrap();
        assert!(exts.basic_constraints.ca);
        assert_eq!(exts.basic_constraints.path_len_constraint, Some(1));
    }

    #[test]
    fn test_parse_extensions_key_usage() {
        // KeyUsage: keyCertSign + cRLSign = 0x06
        let ku_value = &[0x03, 0x02, 0x01, 0x06];
        let ext = build_extension(OID_KEY_USAGE, true, ku_value);
        let wrapped = wrap_extensions(&ext);

        let mut parser = DerParser::new(&wrapped);
        let exts = parse_extensions(&mut parser, wrapped.len()).unwrap();
        assert_eq!(exts.key_usage, 0x06);
    }

    #[test]
    fn test_parse_extensions_eku() {
        // EKU: serverAuth
        let mut eku_inner = alloc::vec::Vec::new();
        eku_inner.push(0x06);
        eku_inner.push(OID_EKU_SERVER_AUTH.len() as u8);
        eku_inner.extend_from_slice(OID_EKU_SERVER_AUTH);
        let mut eku_value = vec![0x30];
        push_der_length(&mut eku_value, eku_inner.len());
        eku_value.extend_from_slice(&eku_inner);

        let ext = build_extension(OID_EXT_KEY_USAGE, false, &eku_value);
        let wrapped = wrap_extensions(&ext);

        let mut parser = DerParser::new(&wrapped);
        let exts = parse_extensions(&mut parser, wrapped.len()).unwrap();
        assert_eq!(exts.ext_key_usage, vec![ExtKeyUsage::ServerAuth]);
    }

    #[test]
    fn test_parse_extensions_ski() {
        let kid: [u8; 20] = [0xDE; 20];
        let mut ski_value = vec![0x04, 0x14];
        ski_value.extend_from_slice(&kid);

        let ext = build_extension(OID_SUBJECT_KEY_ID, false, &ski_value);
        let wrapped = wrap_extensions(&ext);

        let mut parser = DerParser::new(&wrapped);
        let exts = parse_extensions(&mut parser, wrapped.len()).unwrap();
        assert_eq!(exts.subject_key_id, Some(kid.to_vec()));
    }

    #[test]
    fn test_parse_extensions_aki() {
        let kid: [u8; 20] = [0xAB; 20];
        let mut aki_inner = vec![0x80, 0x14];
        aki_inner.extend_from_slice(&kid);
        let mut aki_value = vec![0x30];
        push_der_length(&mut aki_value, aki_inner.len());
        aki_value.extend_from_slice(&aki_inner);

        let ext = build_extension(OID_AUTHORITY_KEY_ID, false, &aki_value);
        let wrapped = wrap_extensions(&ext);

        let mut parser = DerParser::new(&wrapped);
        let exts = parse_extensions(&mut parser, wrapped.len()).unwrap();
        assert_eq!(exts.authority_key_id, Some(kid.to_vec()));
    }

    #[test]
    fn test_parse_extensions_unknown_extension_skipped() {
        // Unknown OID → silently skipped, default extensions returned
        let unknown_oid = &[0x55, 0x1D, 0xFF]; // fake OID
        let value = &[0x04, 0x02, 0xAA, 0xBB]; // OCTET STRING { AA BB }
        let ext = build_extension(unknown_oid, false, value);
        let wrapped = wrap_extensions(&ext);

        let mut parser = DerParser::new(&wrapped);
        let exts = parse_extensions(&mut parser, wrapped.len()).unwrap();
        assert!(!exts.basic_constraints.ca);
        assert_eq!(exts.key_usage, 0);
        assert!(exts.ext_key_usage.is_empty());
        assert!(exts.subject_key_id.is_none());
        assert!(exts.authority_key_id.is_none());
    }

    #[test]
    fn test_parse_extensions_multiple_extensions() {
        // BC(ca=true, pathLen=0) + KU(keyCertSign+cRLSign) + EKU(serverAuth) + SKI
        let bc_value: &[u8] = &[0x30, 0x06, 0x01, 0x01, 0xFF, 0x02, 0x01, 0x00];
        let bc_ext = build_extension(OID_BASIC_CONSTRAINTS, true, bc_value);

        let ku_value: &[u8] = &[0x03, 0x02, 0x01, 0x06];
        let ku_ext = build_extension(OID_KEY_USAGE, true, ku_value);

        let mut eku_inner = alloc::vec::Vec::new();
        eku_inner.push(0x06);
        eku_inner.push(OID_EKU_SERVER_AUTH.len() as u8);
        eku_inner.extend_from_slice(OID_EKU_SERVER_AUTH);
        let mut eku_value = vec![0x30];
        push_der_length(&mut eku_value, eku_inner.len());
        eku_value.extend_from_slice(&eku_inner);
        let eku_ext = build_extension(OID_EXT_KEY_USAGE, false, &eku_value);

        let kid: [u8; 20] = [0x42; 20];
        let mut ski_value = vec![0x04, 0x14];
        ski_value.extend_from_slice(&kid);
        let ski_ext = build_extension(OID_SUBJECT_KEY_ID, false, &ski_value);

        let mut all_exts = alloc::vec::Vec::new();
        all_exts.extend_from_slice(&bc_ext);
        all_exts.extend_from_slice(&ku_ext);
        all_exts.extend_from_slice(&eku_ext);
        all_exts.extend_from_slice(&ski_ext);
        let wrapped = wrap_extensions(&all_exts);

        let mut parser = DerParser::new(&wrapped);
        let exts = parse_extensions(&mut parser, wrapped.len()).unwrap();
        assert!(exts.basic_constraints.ca);
        assert_eq!(exts.basic_constraints.path_len_constraint, Some(0));
        assert_eq!(exts.key_usage, 0x06);
        assert_eq!(exts.ext_key_usage, vec![ExtKeyUsage::ServerAuth]);
        assert_eq!(exts.subject_key_id, Some(kid.to_vec()));
    }

    #[test]
    fn test_parse_extensions_critical_flag_parsed() {
        // Extension with critical=true should still parse correctly
        let bc_value = &[0x30, 0x03, 0x01, 0x01, 0xFF]; // CA:true
        let ext = build_extension(OID_BASIC_CONSTRAINTS, true, bc_value);
        let wrapped = wrap_extensions(&ext);

        let mut parser = DerParser::new(&wrapped);
        let exts = parse_extensions(&mut parser, wrapped.len()).unwrap();
        assert!(exts.basic_constraints.ca);
    }

    #[test]
    fn test_parse_extensions_non_critical_flag_parsed() {
        // Extension with critical=false (omitted) should also parse
        let bc_value = &[0x30, 0x03, 0x01, 0x01, 0xFF]; // CA:true
        let ext = build_extension(OID_BASIC_CONSTRAINTS, false, bc_value);
        let wrapped = wrap_extensions(&ext);

        let mut parser = DerParser::new(&wrapped);
        let exts = parse_extensions(&mut parser, wrapped.len()).unwrap();
        assert!(exts.basic_constraints.ca);
    }

    #[test]
    fn test_default_extensions() {
        let exts = X509Extensions::default();
        assert!(!exts.basic_constraints.ca);
        assert_eq!(exts.basic_constraints.path_len_constraint, None);
        assert_eq!(exts.key_usage, 0);
        assert!(exts.ext_key_usage.is_empty());
        assert!(exts.subject_key_id.is_none());
        assert!(exts.authority_key_id.is_none());
    }
}
