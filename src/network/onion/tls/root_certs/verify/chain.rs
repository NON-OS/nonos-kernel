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
use super::lookup::{find_roots_by_subject_dn, find_roots_by_ski};
use super::super::types::TrustedRootCa;
use alloc::vec::Vec;

pub fn verify_chain_to_root(chain: &[X509Certificate]) -> Result<&'static TrustedRootCa, OnionError> {
    serial::print(b"[CERT] verify_chain_to_root ENTER chain_len=");
    serial::print_dec(chain.len() as u64);
    serial::println(b"");
    if chain.is_empty() { return Err(OnionError::CertificateError); }
    let topmost = &chain[chain.len() - 1];
    serial::print(b"[CERT] topmost subj_len=");
    serial::print_dec(topmost.subject_der.len() as u64);
    serial::print(b" iss_len=");
    serial::print_dec(topmost.issuer_der.len() as u64);
    serial::println(b"");
    let verify_cert = if topmost.issuer_der == topmost.subject_der && chain.len() > 1 {
        serial::println(b"[CERT] topmost is self-signed, verifying cert below it");
        &chain[chain.len() - 2]
    } else { topmost };
    serial::println(b"[CERT] calling find_roots_by_subject_dn");
    let candidates = find_roots_by_subject_dn(&verify_cert.issuer_der);
    serial::print(b"[CERT] DN lookup returned ");
    serial::print_dec(candidates.len() as u64);
    serial::println(b" candidates");
    if !candidates.is_empty() {
        serial::print(b"[CERT] found ");
        serial::print_dec(candidates.len() as u64);
        serial::println(b" candidate roots by DN");
        let filtered: Vec<&'static TrustedRootCa> = if let Some(ref aki) = verify_cert.extensions.authority_key_id {
            let ski_filtered: Vec<_> = candidates.iter()
                .filter(|root| root.ski.map_or(true, |ski| ski == aki.as_slice()))
                .copied().collect();
            if ski_filtered.is_empty() {
                serial::println(b"[CERT] AKI->SKI filter eliminated all, using DN-only");
                candidates
            } else {
                serial::print(b"[CERT] AKI->SKI filtered to ");
                serial::print_dec(ski_filtered.len() as u64);
                serial::println(b" candidates");
                ski_filtered
            }
        } else { candidates };
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
    Err(OnionError::CertificateError)
}
