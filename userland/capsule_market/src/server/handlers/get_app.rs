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

//! `OP_GET_APP` handler. Caller sends a `(listing_id_len, listing_id)`
//! payload; capsule responds with publisher details and release
//! count. The caller drills into a specific release with
//! `OP_GET_RELEASE`.

extern crate alloc;

use alloc::vec::Vec;

use crate::protocol::{Request, E_INVAL, E_MSGSIZE, E_NODATA};
use crate::server::error::reply_status;
use crate::server::payload::{body_slot, reply_with_body};
use crate::store::Store;

pub(crate) fn handle(store: &Store, body: &[u8], req: &Request, tx: &mut [u8]) {
    let accepted = match store.current() {
        Some(a) => a,
        None => return reply_status(tx, req, E_NODATA),
    };
    let listing_id = match read_lp_string(body) {
        Some(s) => s,
        None => return reply_status(tx, req, E_INVAL),
    };
    let entry = match accepted.index.entries.iter().find(|e| e.listing_id == listing_id) {
        Some(e) => e,
        None => return reply_status(tx, req, E_NODATA),
    };

    let mut out: Vec<u8> = Vec::new();
    write_lp_string(&mut out, &entry.listing_id);
    out.extend_from_slice(&entry.capsule_id);
    write_lp_string(&mut out, &entry.name);
    write_lp_string(&mut out, &entry.publisher_name);
    out.extend_from_slice(&entry.publisher_pubkey);
    write_lp_string(&mut out, &entry.description);
    out.extend_from_slice(&(entry.releases.len() as u32).to_le_bytes());

    let body_len = out.len();
    let slot = match body_slot(tx, body_len) {
        Some(s) => s,
        None => return reply_status(tx, req, E_MSGSIZE),
    };
    slot.copy_from_slice(&out);
    reply_with_body(tx, req, body_len);
}

fn read_lp_string(buf: &[u8]) -> Option<&str> {
    if buf.len() < 4 {
        return None;
    }
    let len = u32::from_le_bytes(buf[0..4].try_into().ok()?) as usize;
    let body = buf.get(4..4 + len)?;
    core::str::from_utf8(body).ok()
}

fn write_lp_string(out: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}
