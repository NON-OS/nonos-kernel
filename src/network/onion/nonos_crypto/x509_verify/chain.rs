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
use crate::sys::serial;
use super::super::types::X509Certificate;
use super::super::x509_time::check_time_validity;
use super::signature::{verify_self_signed, verify_signature};

pub(crate) fn verify_chain(chain: &[X509Certificate], now_ms: u64) -> Result<(), OnionError> {
    if chain.is_empty() {
        serial::println(b"[X509] verify_chain: empty chain");
        return Err(OnionError::CertificateError);
    }
    serial::print(b"[X509] verify_chain: ");
    serial::print_dec(chain.len() as u64);
    serial::println(b" certs");
    for (idx, cert) in chain.iter().enumerate() {
        if let Err(e) = check_time_validity(cert, now_ms) {
            serial::print(b"[X509] cert ");
            serial::print_dec(idx as u64);
            serial::println(b" time validity failed");
            return Err(e);
        }
    }
    for i in 0..chain.len() - 1 {
        let cert = &chain[i];
        let issuer = &chain[i + 1];
        serial::print(b"[X509] checking cert ");
        serial::print_dec(i as u64);
        serial::print(b" -> issuer ");
        serial::print_dec((i + 1) as u64);
        serial::println(b"");
        if cert.issuer_der != issuer.subject_der {
            serial::println(b"[X509] ERROR: issuer/subject mismatch");
            serial::print(b"[X509] cert issuer len=");
            serial::print_dec(cert.issuer_der.len() as u64);
            serial::print(b" subject len=");
            serial::print_dec(issuer.subject_der.len() as u64);
            serial::println(b"");
            return Err(OnionError::CertificateError);
        }
        serial::println(b"[X509] issuer/subject match OK");
        if let Err(e) = verify_signature(cert, issuer) {
            serial::println(b"[X509] ERROR: signature verify failed");
            serial::print(b"[X509] sig_alg oid len=");
            serial::print_dec(cert.signature_algorithm.algorithm.components.len() as u64);
            serial::println(b"");
            return Err(e);
        }
        serial::println(b"[X509] signature OK");
    }
    verify_root(chain)
}

fn verify_root(chain: &[X509Certificate]) -> Result<(), OnionError> {
    let root = &chain[chain.len() - 1];
    if root.issuer_der == root.subject_der {
        serial::println(b"[X509] verifying self-signed root");
        if let Err(e) = verify_self_signed(root) {
            serial::println(b"[X509] ERROR: root self-sign failed");
            return Err(e);
        }
        serial::println(b"[X509] root self-sign OK");
    }
    serial::println(b"[X509] verify_chain: SUCCESS");
    Ok(())
}
