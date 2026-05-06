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

//! `OP_GET_RELEASE` handler. Caller sends `(listing_id, release_id)`;
//! capsule responds with the release detail (hashes, package URL,
//! supported arches, kernel ABI floor, validation note).

extern crate alloc;

use alloc::vec::Vec;

use nonos_marketplace_abi::CapsuleRelease;

use crate::protocol::{Request, E_INVAL, E_MSGSIZE, E_NODATA};
use crate::server::error::reply_status;
use crate::server::payload::{body_slot, reply_with_body};
use crate::store::Store;

pub(crate) fn handle(store: &Store, body: &[u8], req: &Request, tx: &mut [u8]) {
    let accepted = match store.current() {
        Some(a) => a,
        None => return reply_status(tx, req, E_NODATA),
    };
    let (listing_id, release_id) = match parse_pair(body) {
        Some(p) => p,
        None => return reply_status(tx, req, E_INVAL),
    };
    let release = accepted
        .index
        .entries
        .iter()
        .find(|e| e.listing_id == listing_id)
        .and_then(|e| e.releases.iter().find(|r| r.release_id == release_id));
    let release = match release {
        Some(r) => r,
        None => return reply_status(tx, req, E_NODATA),
    };

    let out = encode_release(release);
    let body_len = out.len();
    let slot = match body_slot(tx, body_len) {
        Some(s) => s,
        None => return reply_status(tx, req, E_MSGSIZE),
    };
    slot.copy_from_slice(&out);
    reply_with_body(tx, req, body_len);
}

fn encode_release(rel: &CapsuleRelease) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    write_lp_string(&mut out, &rel.release_id);
    out.extend_from_slice(&rel.manifest_hash);
    out.extend_from_slice(&rel.package_hash);
    write_lp_string(&mut out, &rel.package_url);
    out.extend_from_slice(&(rel.publisher_signature.len() as u32).to_le_bytes());
    out.extend_from_slice(&rel.publisher_signature);
    out.extend_from_slice(&(rel.supported_arches.len() as u32).to_le_bytes());
    for arch in &rel.supported_arches {
        write_lp_string(&mut out, arch);
    }
    out.extend_from_slice(&rel.kernel_abi_min.to_le_bytes());
    out.extend_from_slice(&(rel.required_capabilities.len() as u32).to_le_bytes());
    for cap in &rel.required_capabilities {
        write_lp_string(&mut out, cap);
    }
    out.push(rel.validation.status as u8);
    write_lp_string(&mut out, &rel.validation.note);
    write_lp_string(&mut out, &rel.validation.validator_id);
    out.extend_from_slice(&rel.validation.validated_at_ms.to_le_bytes());
    out
}

fn parse_pair(buf: &[u8]) -> Option<(&str, &str)> {
    let (first, rest) = take_lp(buf)?;
    let (second, _) = take_lp(rest)?;
    Some((core::str::from_utf8(first).ok()?, core::str::from_utf8(second).ok()?))
}

fn take_lp(buf: &[u8]) -> Option<(&[u8], &[u8])> {
    if buf.len() < 4 {
        return None;
    }
    let len = u32::from_le_bytes(buf[0..4].try_into().ok()?) as usize;
    let body = buf.get(4..4 + len)?;
    let rest = &buf[4 + len..];
    Some((body, rest))
}

fn write_lp_string(out: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}
