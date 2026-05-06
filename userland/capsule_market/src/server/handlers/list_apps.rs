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

//! `OP_LIST_APPS` handler. Returns a compact summary tuple per
//! listing — `(listing_id, capsule_id, name, install_ready)` —
//! suitable for a market UI without flooding the IPC channel with
//! full release detail. Detail comes via `OP_GET_APP` /
//! `OP_GET_RELEASE`.

extern crate alloc;

use alloc::vec::Vec;

use crate::install_ready;
use crate::protocol::{Request, E_MSGSIZE, E_NODATA};
use crate::server::error::reply_status;
use crate::server::payload::{body_slot, reply_with_body};
use crate::store::Store;

pub(crate) fn handle(store: &Store, req: &Request, tx: &mut [u8]) {
    let accepted = match store.current() {
        Some(a) => a,
        None => return reply_status(tx, req, E_NODATA),
    };

    let mut body: Vec<u8> = Vec::new();
    let count = accepted.index.entries.len() as u32;
    body.extend_from_slice(&count.to_le_bytes());

    for entry in &accepted.index.entries {
        let any_ready = entry.releases.iter().any(|rel| {
            install_ready::evaluate(accepted.signature_verified, entry, rel).install_ready
        });
        write_lp_string(&mut body, &entry.listing_id);
        body.extend_from_slice(&entry.capsule_id);
        write_lp_string(&mut body, &entry.name);
        body.push(any_ready as u8);
    }

    let body_len = body.len();
    let slot = match body_slot(tx, body_len) {
        Some(s) => s,
        None => return reply_status(tx, req, E_MSGSIZE),
    };
    slot.copy_from_slice(&body);
    reply_with_body(tx, req, body_len);
}

fn write_lp_string(out: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}
