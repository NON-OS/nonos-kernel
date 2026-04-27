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
use crate::network::onion::nonos_crypto::{X509Certificate, verify_signature_with_spki_der};
use crate::sys::serial;
use super::lookup::{find_roots_by_subject_dn, find_roots_by_ski, root_lookup_stats};
use super::super::types::TrustedRootCa;
use alloc::vec::Vec;

pub fn verify_chain_to_root(chain: &[X509Certificate]) -> Result<&'static TrustedRootCa, OnionError> {
    serial::print(b"[CERT] root anchor chain_len=");
    serial::print_dec(chain.len() as u64);
    serial::println(b"");
    if chain.is_empty() { return Err(OnionError::CertificateError); }
    let topmost = &chain[chain.len() - 1];
    let topmost_subject_candidates = find_roots_by_subject_dn(&topmost.subject_der);
    if !topmost_subject_candidates.is_empty() {
        for root in &topmost_subject_candidates {
            if root.spki_der == topmost.public_key.raw_spki.as_slice() {
                serial::print(b"[CERT] root anchor OK: ");
                let name_bytes = root.name.as_bytes();
                serial::print(&name_bytes[..name_bytes.len().min(40)]);
                serial::println(b"");
                return Ok(root);
            }
        }
        serial::println(b"[CERT] topmost subject match found, but SPKI mismatch");
    }
    let verify_cert = if topmost.issuer_der == topmost.subject_der && chain.len() > 1 {
        &chain[chain.len() - 2]
    } else { topmost };
    if let Some(ref aki) = verify_cert.extensions.authority_key_id {
        serial::print(b"[CERT] root lookup AKI len=");
        serial::print_dec(aki.len() as u64);
        serial::println(b"");
        let aki_candidates = find_roots_by_ski(aki.as_slice());
        if !aki_candidates.is_empty() {
            for root in &aki_candidates {
                if verify_signature_with_spki_der(verify_cert, root.spki_der).is_ok() {
                    serial::print(b"[CERT] root anchor OK: ");
                    let name_bytes = root.name.as_bytes();
                    serial::print(&name_bytes[..name_bytes.len().min(40)]);
                    serial::println(b"");
                    return Ok(root);
                }
            }
        }
    }
    let candidates = find_roots_by_subject_dn(&verify_cert.issuer_der);
    serial::print(b"[CERT] root lookup DN candidates=");
    serial::print_dec(candidates.len() as u64);
    serial::println(b"");
    if candidates.is_empty() {
        serial::print(b"[CERT] issuer DN first bytes: ");
        for i in 0..verify_cert.issuer_der.len().min(16) {
            serial::print_hex(verify_cert.issuer_der[i] as u64);
            serial::print(b" ");
        }
        serial::println(b"");
    }
    if !candidates.is_empty() {
        let filtered: Vec<&'static TrustedRootCa> = if let Some(ref aki) = verify_cert.extensions.authority_key_id {
            let ski_filtered: Vec<_> = candidates.iter()
                .filter(|root| root.ski.map_or(true, |ski| ski == aki.as_slice()))
                .copied().collect();
            if ski_filtered.is_empty() {
                candidates
            } else {
                ski_filtered
            }
        } else { candidates };
        serial::print(b"[CERT] root verify candidates=");
        serial::print_dec(filtered.len() as u64);
        serial::println(b"");
        for root in &filtered {
            if verify_signature_with_spki_der(verify_cert, root.spki_der).is_ok() {
                serial::print(b"[CERT] root anchor OK: ");
                let name_bytes = root.name.as_bytes();
                serial::print(&name_bytes[..name_bytes.len().min(40)]);
                serial::println(b"");
                return Ok(root);
            }
        }
        serial::println(b"[CERT] DN candidates found but signature verification failed");
    }
    let aki = verify_cert.extensions.authority_key_id.as_ref().map(|id| id.as_slice());
    let stats = root_lookup_stats(&verify_cert.issuer_der, aki);
    serial::print(b"[CERT] root lookup failed issuer_len=");
    serial::print_dec(verify_cert.issuer_der.len() as u64);
    serial::print(b" aki_len=");
    serial::print_dec(aki.map_or(0, |id| id.len()) as u64);
    serial::print(b" exact_dn=");
    serial::print_dec(stats.exact_subject as u64);
    serial::print(b" same_len_dn=");
    serial::print_dec(stats.same_len_subject as u64);
    serial::print(b" ski=");
    serial::print_dec(stats.ski as u64);
    serial::println(b"");
    #[cfg(not(feature = "nonos-secureboot"))]
    {
        if !candidates.is_empty() {
            serial::println(b"[CERT] test mode: allowing DN-matched unverified root");
            return Ok(candidates[0]);
        }
        serial::println(b"[CERT] test mode: no trusted-root fallback without DN match");
        return Err(OnionError::CertificateError);
    }
    #[cfg(feature = "nonos-secureboot")]
    Err(OnionError::CertificateError)
}
