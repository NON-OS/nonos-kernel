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
use super::super::types::X509Certificate;
use super::super::x509_der::DerParser;
use super::x509::X509;
use super::oid::parse_algorithm_identifier;
use super::spki::parse_subject_public_key_info;
use super::tbs::parse_tbs_fields;
use super::extensions::parse_extensions;

impl X509 {
    pub fn parse_der(der: &[u8]) -> Result<X509Certificate, OnionError> {
        crate::sys::serial::print(b"[X509] parse_der len=");
        crate::sys::serial::print_dec(der.len() as u64);
        crate::sys::serial::println(b"");
        let mut parser = DerParser::new(der);
        crate::sys::serial::println(b"[X509] expect outer sequence");
        parser.expect_sequence()?;
        let _outer_len = parser.read_length()?;
        let cert_start = parser.offset;
        if cert_start >= der.len() {
            crate::sys::serial::println(b"[X509] ERROR: cert_start >= len");
            return Err(OnionError::CertificateError);
        }
        crate::sys::serial::println(b"[X509] expect tbs sequence");
        let tbs_start = parser.offset;
        parser.expect_sequence()?;
        let tbs_len = parser.read_length()?;
        let tbs_content_end = parser.offset + tbs_len;
        crate::sys::serial::println(b"[X509] parse_tbs_fields");
        let (not_before_ms, not_after_ms, issuer_der, subject_der) =
            parse_tbs_fields(&mut parser)?;
        crate::sys::serial::println(b"[X509] parse_subject_public_key_info");
        let public_key = parse_subject_public_key_info(&mut parser)?;
        crate::sys::serial::println(b"[X509] parse_extensions");
        let extensions = parse_extensions(&mut parser, tbs_content_end)?;
        parser.offset = tbs_content_end;
        let tbs_certificate = der[tbs_start..tbs_content_end].to_vec();
        crate::sys::serial::println(b"[X509] parse sig_algorithm");
        let signature_algorithm = parse_algorithm_identifier(&mut parser)?;
        crate::sys::serial::println(b"[X509] reading signature");
        parser.expect_tag(0x03)?;
        let sig_len = parser.read_length()?;
        parser.skip(1)?;
        let signature = parser.read_bytes(sig_len - 1)?.to_vec();
        crate::sys::serial::println(b"[X509] parse OK");
        Ok(X509Certificate {
            tbs_certificate, signature_algorithm, signature, public_key,
            not_before_ms, not_after_ms, extensions, subject_der, issuer_der,
        })
    }
}
