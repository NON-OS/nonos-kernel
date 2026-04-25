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

use super::super::crypto_provider::crypto;
use super::super::keys::{expand_label, Secret};
use super::super::types::HSType;
use super::wrap::wrap_handshake;
use crate::network::onion::nonos_crypto::constant_time_eq;
use alloc::vec::Vec;

pub(in crate::network::onion::tls) fn build_finished(
    secret: &Secret,
    transcript_hash: &[u8],
) -> Vec<u8> {
    let hl = secret.len;
    let finished_key = expand_label(secret.as_slice(), b"finished", &[], hl);
    let c = crypto();
    if hl == 48 {
        let mut mac = [0u8; 48];
        c.hmac_sha384(&finished_key[..hl], transcript_hash, &mut mac);
        wrap_handshake(HSType::Finished as u8, &mac)
    } else {
        let mut mac = [0u8; 32];
        c.hmac_sha256(&finished_key[..hl], transcript_hash, &mut mac);
        wrap_handshake(HSType::Finished as u8, &mac)
    }
}

pub(in crate::network::onion::tls) fn verify_finished_with_payload(
    secret: &Secret,
    th: &[u8],
    received_mac: &[u8],
) -> bool {
    let hl = secret.len;
    let finished_key = expand_label(secret.as_slice(), b"finished", &[], hl);
    let c = crypto();
    if hl == 48 {
        let mut mac = [0u8; 48];
        c.hmac_sha384(&finished_key[..hl], th, &mut mac);
        constant_time_eq(&mac, received_mac)
    } else {
        let mut mac = [0u8; 32];
        c.hmac_sha256(&finished_key[..hl], th, &mut mac);
        constant_time_eq(&mac, received_mac)
    }
}

pub(in crate::network::onion::tls) fn build_cert_verify_context(th: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(64 + 33 + 1 + th.len());
    v.extend_from_slice(&[0x20u8; 64]);
    v.extend_from_slice(b"TLS 1.3, server CertificateVerify");
    v.push(0u8);
    v.extend_from_slice(th);
    v
}
