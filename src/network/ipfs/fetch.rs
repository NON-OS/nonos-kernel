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
use alloc::vec::Vec;
use super::{gateway, cid};

#[derive(Debug)]
pub enum FetchError { InvalidCid, Network, Verify, TooLarge }

pub const MAX_SIZE: usize = 64 * 1024 * 1024;

pub fn fetch(content_id: &str) -> Result<Vec<u8>, FetchError> {
    if !cid::validate(content_id) { return Err(FetchError::InvalidCid); }
    for _ in 0..gateway::GATEWAYS.len() {
        let url = gateway::get_url(content_id);
        match crate::network::http::get(&url, &[], 60000) {
            Ok(resp) => {
                if resp.body.len() > MAX_SIZE { return Err(FetchError::TooLarge); }
                return Ok(resp.body);
            }
            Err(_) => gateway::rotate_gateway(),
        }
    }
    Err(FetchError::Network)
}

pub fn fetch_verified(content_id: &str) -> Result<Vec<u8>, FetchError> {
    let data = fetch(content_id)?;
    if !cid::verify_content(&data, content_id) { return Err(FetchError::Verify); }
    Ok(data)
}

pub fn fetch_capsule(content_id: &str) -> Result<Vec<u8>, FetchError> {
    let data = fetch(content_id)?;
    if data.len() < 64 { return Err(FetchError::Verify); }
    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if magic != crate::capsule::NOXC_MAGIC { return Err(FetchError::Verify); }
    Ok(data)
}
