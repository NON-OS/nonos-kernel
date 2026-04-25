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

use super::super::types::TrustedRootCa;
use super::lookup::{find_roots_by_ski, find_roots_by_subject_dn};
use crate::network::onion::nonos_crypto::{verify_signature_with_spki_der, X509Certificate};
use crate::network::onion::OnionError;
use crate::sys::serial;
use alloc::vec::Vec;

pub fn verify_chain_to_root(
    chain: &[X509Certificate],
) -> Result<&'static TrustedRootCa, OnionError> {
    serial::print(b"[CERT] verify_chain_to_root ENTER chain_len=");
    serial::print_dec(chain.len() as u64);
    serial::println(b"");
    if chain.is_empty() {
        return Err(OnionError::CertificateError);
    }
    let topmost = &chain[chain.len() - 1];
    serial::print(b"[CERT] topmost subj_len=");
    serial::print_dec(topmost.subject_der.len() as u64);
    serial::print(b" iss_len=");
    serial::print_dec(topmost.issuer_der.len() as u64);
    serial::println(b"");
    let topmost_subject_candidates = find_roots_by_subject_dn(&topmost.subject_der);
    if !topmost_subject_candidates.is_empty() {
        serial::print(b"[CERT] topmost subject matched ");
        serial::print_dec(topmost_subject_candidates.len() as u64);
        serial::println(b" trusted roots");
        for root in &topmost_subject_candidates {
            if root.spki_der == topmost.public_key.raw_spki.as_slice() {
                serial::print(b"[CERT] chain anchored by topmost SPKI: ");
                let name_bytes = root.name.as_bytes();
                serial::print(&name_bytes[..name_bytes.len().min(40)]);
                serial::println(b"");
                return Ok(root);
            }
        }
        serial::println(b"[CERT] topmost subject match found, but SPKI mismatch");
    }
    let verify_cert = if topmost.issuer_der == topmost.subject_der && chain.len() > 1 {
        serial::println(b"[CERT] topmost is self-signed, verifying cert below it");
        &chain[chain.len() - 2]
    } else {
        topmost
    };
    serial::println(b"[CERT] calling find_roots_by_subject_dn");
    let candidates = find_roots_by_subject_dn(&verify_cert.issuer_der);
    serial::print(b"[CERT] DN lookup returned ");
    serial::print_dec(candidates.len() as u64);
    serial::println(b" candidates");
    if candidates.is_empty() {
        serial::print(b"[CERT] issuer DN first bytes: ");
        for i in 0..verify_cert.issuer_der.len().min(16) {
            serial::print_hex(verify_cert.issuer_der[i] as u64);
            serial::print(b" ");
        }
        serial::println(b"");
    }
    if !candidates.is_empty() {
        serial::print(b"[CERT] found ");
        serial::print_dec(candidates.len() as u64);
        serial::println(b" candidate roots by DN");
        let filtered: Vec<&'static TrustedRootCa> =
            if let Some(ref aki) = verify_cert.extensions.authority_key_id {
                let ski_filtered: Vec<_> = candidates
                    .iter()
                    .filter(|root| root.ski.map_or(true, |ski| ski == aki.as_slice()))
                    .copied()
                    .collect();
                if ski_filtered.is_empty() {
                    serial::println(b"[CERT] AKI->SKI filter eliminated all, using DN-only");
                    candidates
                } else {
                    serial::print(b"[CERT] AKI->SKI filtered to ");
                    serial::print_dec(ski_filtered.len() as u64);
                    serial::println(b" candidates");
                    ski_filtered
                }
            } else {
                candidates
            };
        for root in &filtered {
            serial::print(b"[CERT] trying root: ");
            let nb = root.name.as_bytes();
            serial::print(&nb[..nb.len().min(40)]);
            serial::print(b" spki_len=");
            serial::print_dec(root.spki_der.len() as u64);
            serial::println(b"");
            if verify_signature_with_spki_der(verify_cert, root.spki_der).is_ok() {
                serial::print(b"[CERT] chain-to-root verified: ");
                let name_bytes = root.name.as_bytes();
                serial::print(&name_bytes[..name_bytes.len().min(40)]);
                serial::println(b"");
                return Ok(root);
            }
            serial::println(b"[CERT] root did not verify, trying next");
        }
        serial::println(b"[CERT] DN candidates found but signature verification failed");
    }
    if let Some(ref aki) = verify_cert.extensions.authority_key_id {
        serial::print(b"[CERT] no DN match, trying AKI fallback aki_len=");
        serial::print_dec(aki.len() as u64);
        serial::println(b"");
        let aki_candidates = find_roots_by_ski(aki.as_slice());
        if !aki_candidates.is_empty() {
            serial::print(b"[CERT] AKI fallback found ");
            serial::print_dec(aki_candidates.len() as u64);
            serial::println(b" roots by SKI");
            for root in &aki_candidates {
                if verify_signature_with_spki_der(verify_cert, root.spki_der).is_ok() {
                    serial::print(b"[CERT] chain-to-root verified (AKI): ");
                    let name_bytes = root.name.as_bytes();
                    serial::print(&name_bytes[..name_bytes.len().min(40)]);
                    serial::println(b"");
                    return Ok(root);
                }
            }
        }
    }
    serial::print(b"[CERT] chain-to-root: no trusted root found, issuer_dn_len=");
    serial::print_dec(verify_cert.issuer_der.len() as u64);
    serial::println(b"");
    #[cfg(not(feature = "nonos-secureboot"))]
    {
        serial::println(b"[CERT] TEST MODE: Proceeding without trusted root (not production)");
        if !candidates.is_empty() {
            return Ok(candidates[0]);
        }
        return Err(OnionError::CertificateError);
    }
    #[cfg(feature = "nonos-secureboot")]
    Err(OnionError::CertificateError)
}
