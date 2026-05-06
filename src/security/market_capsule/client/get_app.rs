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

//! `OP_GET_APP`. Caller passes a `listing_id`; the kernel client
//! ships it as a length-prefixed string and lifts the response
//! into [`AppSummary`]. The kernel does not consume the per-app
//! detail itself — installer / UI capsules consume it — but the
//! summary keeps the on-the-wire fields in named struct fields so
//! callers do not have to re-implement the byte layout.

use alloc::string::String;
use alloc::vec::Vec;

use super::super::capability::gate_call;
use super::super::error::MarketError;
use super::super::protocol::{encode_request, OP_GET_APP};
use super::seq::next_request_id;
use super::status_map::lift;
use super::transport::round_trip;

pub struct AppSummary {
    pub listing_id: String,
    pub capsule_id: [u8; 32],
    pub name: String,
    pub publisher_name: String,
    pub publisher_pubkey: [u8; 32],
    pub description: String,
    pub release_count: u32,
}

pub fn get_app(listing_id: &str) -> Result<AppSummary, MarketError> {
    let _caller = gate_call()?;
    let mut body: Vec<u8> = Vec::with_capacity(4 + listing_id.len());
    body.extend_from_slice(&(listing_id.len() as u32).to_le_bytes());
    body.extend_from_slice(listing_id.as_bytes());

    let request_id = next_request_id();
    let frame = encode_request(OP_GET_APP, 0, request_id, &body);
    let resp = round_trip(request_id, frame)?;
    if resp.status != 0 {
        return Err(lift(resp.status));
    }
    parse(&resp.body).ok_or(MarketError::ProtocolMismatch)
}

fn parse(buf: &[u8]) -> Option<AppSummary> {
    let mut cur = buf;
    let listing_id = take_string(&mut cur)?;
    let capsule_id = take_bytes32(&mut cur)?;
    let name = take_string(&mut cur)?;
    let publisher_name = take_string(&mut cur)?;
    let publisher_pubkey = take_bytes32(&mut cur)?;
    let description = take_string(&mut cur)?;
    if cur.len() < 4 {
        return None;
    }
    let release_count = u32::from_le_bytes(cur[0..4].try_into().ok()?);
    Some(AppSummary {
        listing_id,
        capsule_id,
        name,
        publisher_name,
        publisher_pubkey,
        description,
        release_count,
    })
}

fn take_string(cur: &mut &[u8]) -> Option<String> {
    if cur.len() < 4 {
        return None;
    }
    let len = u32::from_le_bytes(cur[0..4].try_into().ok()?) as usize;
    let body = cur.get(4..4 + len)?;
    let s = core::str::from_utf8(body).ok()?.into();
    *cur = &cur[4 + len..];
    Some(s)
}

fn take_bytes32(cur: &mut &[u8]) -> Option<[u8; 32]> {
    if cur.len() < 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&cur[..32]);
    *cur = &cur[32..];
    Some(out)
}
