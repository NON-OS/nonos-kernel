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

extern crate alloc;

use crate::network::nym::error::NymError;
use crate::network::nym::types::{MixNode, MixNodeId};
use alloc::string::String;
use alloc::vec::Vec;

pub fn fetch_mixnodes() -> Result<Vec<MixNode>, NymError> {
    let cache = super::cache::get_directory_cache().lock();
    if !cache.mixnodes.is_empty() {
        return Ok(cache.mixnodes.clone());
    }
    drop(cache);
    let url = super::validators::VALIDATORS[0].mixnodes_url();
    let response =
        crate::network::http_client::fetch(&url).map_err(|_| NymError::DirectoryFetchFailed)?;
    parse_mixnodes_response(&response)
}

pub fn select_mixnode_by_layer(layer: u8) -> Result<MixNode, NymError> {
    let cache = super::cache::get_directory_cache().lock();
    let candidates: Vec<_> =
        cache.mixnodes.iter().filter(|n| n.layer == layer && n.is_healthy()).collect();
    if candidates.is_empty() {
        return Err(NymError::NoAvailableMixNodes);
    }
    let idx = crate::crypto::random_u32() as usize % candidates.len();
    Ok(candidates[idx].clone())
}

fn parse_mixnodes_response(data: &[u8]) -> Result<Vec<MixNode>, NymError> {
    let json = core::str::from_utf8(data).map_err(|_| NymError::DirectoryFetchFailed)?;
    let mut nodes = Vec::new();
    for line in json.lines() {
        if let Some(node) = parse_mixnode_entry(line) {
            nodes.push(node);
        }
    }
    if nodes.is_empty() {
        return Err(NymError::NoAvailableMixNodes);
    }
    let mut cache = super::cache::get_directory_cache().lock();
    cache.mixnodes = nodes.clone();
    cache.last_mixnode_fetch = crate::time::timestamp_millis();
    Ok(nodes)
}

fn parse_mixnode_entry(entry: &str) -> Option<MixNode> {
    let id_start = entry.find("\"identity_key\":\"")?;
    let id_end = entry[id_start + 16..].find('"')?;
    let id_str = &entry[id_start + 16..id_start + 16 + id_end];
    let id_bytes = decode_base58(id_str)?;
    if id_bytes.len() != 32 {
        return None;
    }
    let mut identity = [0u8; 32];
    identity.copy_from_slice(&id_bytes);
    Some(MixNode {
        id: MixNodeId(identity),
        identity_key: identity,
        sphinx_key: identity,
        host: String::from("mix.nymtech.net"),
        mix_port: 1789,
        layer: 1,
        version: String::from("1.0"),
        stake: 1000,
        performance: 100,
    })
}

const BASE58_ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn decode_base58(s: &str) -> Option<Vec<u8>> {
    let mut result = Vec::new();
    for c in s.bytes() {
        let val = BASE58_ALPHABET.iter().position(|&x| x == c)? as u32;
        let mut carry = val;
        for byte in result.iter_mut().rev() {
            carry += (*byte as u32) * 58;
            *byte = (carry & 0xFF) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            result.insert(0, (carry & 0xFF) as u8);
            carry >>= 8;
        }
    }
    for c in s.bytes() {
        if c == b'1' {
            result.insert(0, 0);
        } else {
            break;
        }
    }
    Some(result)
}
