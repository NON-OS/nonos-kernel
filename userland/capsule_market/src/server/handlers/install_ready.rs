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

//! `OP_INSTALL_READY` handler. Returns the install-readiness
//! verdict for a specific (listing, release) pair as a six-byte
//! body: one byte per check plus the AND-result. The AND-result
//! is the only bit a sane caller acts on; the per-check bits let
//! a UI explain which gate refused the install.

use crate::install_ready::evaluate;
use crate::protocol::{Request, E_INVAL, E_NODATA};
use crate::server::error::reply_status;
use crate::server::payload::{body_slot, reply_with_body};
use crate::store::Store;

const READINESS_LEN: usize = 6;

pub(crate) fn handle(store: &Store, body: &[u8], req: &Request, tx: &mut [u8]) {
    let accepted = match store.current() {
        Some(a) => a,
        None => return reply_status(tx, req, E_NODATA),
    };
    let (listing_id, release_id) = match parse_pair(body) {
        Some(p) => p,
        None => return reply_status(tx, req, E_INVAL),
    };
    let pair = accepted
        .index
        .entries
        .iter()
        .find(|e| e.listing_id == listing_id)
        .and_then(|e| e.releases.iter().find(|r| r.release_id == release_id).map(|r| (e, r)));
    let (entry, release) = match pair {
        Some(p) => p,
        None => return reply_status(tx, req, E_NODATA),
    };

    let verdict = evaluate(accepted.signature_verified, entry, release);
    let slot = match body_slot(tx, READINESS_LEN) {
        Some(s) => s,
        None => return reply_status(tx, req, E_INVAL),
    };
    slot[0] = verdict.install_ready as u8;
    slot[1] = verdict.index_signature_valid as u8;
    slot[2] = verdict.package_url_present as u8;
    slot[3] = verdict.publisher_signature_present as u8;
    slot[4] = verdict.validation_passed as u8;
    slot[5] = verdict.arch_match as u8;
    reply_with_body(tx, req, READINESS_LEN);
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
