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

use super::super::types::{TLS_1_2, TLS_1_3};
use crate::network::onion::OnionError;
use alloc::vec::Vec;

/// RFC 8446 §4.1.3: HelloRetryRequest uses this special random value
const HRR_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

/// Parsed result from a ServerHello message
pub enum ServerHelloResult {
    /// Normal ServerHello with key share
    Normal {
        suite: u16,
        server_pub: Vec<u8>,
        server_group: u16,
        random: [u8; 32],
        /// If the server accepted our PSK, this is the selected identity index (0x0029 ext).
        psk_selected: Option<u16>,
    },
    /// HelloRetryRequest — server wants a different key share group
    HelloRetryRequest { suite: u16, selected_group: u16, cookie: Option<Vec<u8>> },
}

pub fn is_hello_retry_request(random: &[u8; 32]) -> bool {
    random == &HRR_RANDOM
}

pub fn parse_server_hello(body: &[u8]) -> Result<ServerHelloResult, OnionError> {
    if body.len() < 40 {
        return Err(OnionError::InvalidCell);
    }
    let mut off = 0usize;
    if u16::from_be_bytes([body[off], body[off + 1]]) != TLS_1_2 {
        return Err(OnionError::CryptoError);
    }
    off += 2;
    let mut random = [0u8; 32];
    random.copy_from_slice(&body[off..off + 32]);
    off += 32;
    let session_id_len = body[off] as usize;
    off += 1;
    if body.len() < off + session_id_len + 5 {
        return Err(OnionError::InvalidCell);
    }
    off += session_id_len;
    let suite = u16::from_be_bytes([body[off], body[off + 1]]);
    off += 3;
    let ext_len = u16::from_be_bytes([body[off], body[off + 1]]) as usize;
    off += 2;
    if body.len() < off + ext_len {
        return Err(OnionError::InvalidCell);
    }
    let mut exts = &body[off..off + ext_len];

    let is_hrr = is_hello_retry_request(&random);

    let mut seen_sv = false;
    let mut seen_ks = false;
    let mut server_pub = Vec::new();
    let mut server_group: u16 = 0;
    let mut cookie: Option<Vec<u8>> = None;
    let mut psk_selected: Option<u16> = None;

    while exts.len() >= 4 {
        let ety = u16::from_be_bytes([exts[0], exts[1]]);
        let el = u16::from_be_bytes([exts[2], exts[3]]) as usize;
        if exts.len() < 4 + el {
            return Err(OnionError::InvalidCell);
        }
        let eb = &exts[4..4 + el];
        match ety {
            // supported_versions
            0x002b => {
                if el != 2 || u16::from_be_bytes([eb[0], eb[1]]) != TLS_1_3 {
                    return Err(OnionError::CryptoError);
                }
                seen_sv = true;
            }
            // key_share
            0x0033 => {
                if is_hrr {
                    // HRR key_share contains only the selected group (2 bytes)
                    if el < 2 {
                        return Err(OnionError::CryptoError);
                    }
                    server_group = u16::from_be_bytes([eb[0], eb[1]]);
                } else {
                    // Normal ServerHello: group(2) + key_len(2) + key_data
                    if el < 4 {
                        return Err(OnionError::CryptoError);
                    }
                    server_group = u16::from_be_bytes([eb[0], eb[1]]);
                    let key_len = u16::from_be_bytes([eb[2], eb[3]]) as usize;
                    if el < 4 + key_len {
                        return Err(OnionError::CryptoError);
                    }
                    server_pub = eb[4..4 + key_len].to_vec();
                }
                seen_ks = true;
            }
            // cookie (HRR only, RFC 8446 §4.2.2)
            0x002c => {
                if is_hrr && el >= 2 {
                    let cookie_len = u16::from_be_bytes([eb[0], eb[1]]) as usize;
                    if el >= 2 + cookie_len {
                        cookie = Some(eb[2..2 + cookie_len].to_vec());
                    }
                }
            }
            // pre_shared_key (RFC 8446 §4.2.11) — selected identity index
            0x0029 => {
                if !is_hrr && el == 2 {
                    psk_selected = Some(u16::from_be_bytes([eb[0], eb[1]]));
                }
            }
            _ => {}
        }
        exts = &exts[4 + el..];
    }

    if !(seen_sv && seen_ks) {
        return Err(OnionError::CryptoError);
    }

    if is_hrr {
        Ok(ServerHelloResult::HelloRetryRequest { suite, selected_group: server_group, cookie })
    } else {
        Ok(ServerHelloResult::Normal { suite, server_pub, server_group, random, psk_selected })
    }
}

pub fn has_tls12_downgrade_sentinel(random: &[u8; 32]) -> bool {
    let suffix = &random[24..32];
    let tls12_sentinel = [0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01];
    let tls11_sentinel = [0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x00];
    suffix == &tls12_sentinel || suffix == &tls11_sentinel
}
