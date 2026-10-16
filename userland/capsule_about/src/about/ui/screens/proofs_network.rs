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

//! Every admitted capsule that holds Network: the complete list of programs on
//! this machine that can send a packet anywhere. Each with the measurement its
//! proof was checked against and whose proof admitted it. Anything not listed
//! here cannot reach the network through any service, because every network
//! service refuses a caller without Network.

use nonos_app_skeleton::PaintBuffer;
use nonos_toolkit::theme::roles;

use crate::about::data::proofs::Snapshot;
use crate::about::data::verify::Attested;

use super::super::card::{self, titled};
use super::super::kv::ROW_H;
use super::super::metrics::{BODY_PX, CARD_PAD};
use super::super::text::{line, top_of};
use super::verify_spawn_row::row;

pub fn height(s: &Snapshot) -> u32 {
    card::OVERHEAD + ROW_H + ROW_H * (s.holders.len().max(1) as u32) + 4
}

pub fn paint(fb: &mut PaintBuffer, y: i32, w: u32, s: &Snapshot) {
    let r = roles();
    let inner = card::inner(w);
    let top = titled(fb, 0, y, w, height(s), b"Can reach the network");
    let note = b"The only programs that can send a packet. Each was proved before it started.";
    line(fb, CARD_PAD, top_of(top, ROW_H, BODY_PX), note, r.muted.argb(), BODY_PX);
    let first = top + ROW_H as i32;
    if s.census.is_none() {
        let msg = b"the kernel did not list them: reading the registry needs AttestRead";
        line(fb, CARD_PAD, top_of(first, ROW_H, BODY_PX), msg, r.muted.argb(), BODY_PX);
        return;
    }
    if s.holders.is_empty() {
        let msg = b"no running capsule holds Network";
        line(fb, CARD_PAD, top_of(first, ROW_H, BODY_PX), msg, r.muted.argb(), BODY_PX);
        return;
    }
    for (i, h) in s.holders.iter().enumerate() {
        let a = Attested {
            pid: h.pid,
            measurement: h.measurement,
            authority: h.authority,
            name: h.name,
            name_len: h.name_len,
        };
        row(fb, CARD_PAD, first + (i as u32 * ROW_H) as i32, inner, &a);
    }
}
