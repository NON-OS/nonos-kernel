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

//! What the machine would hand a verifier who asked what it is running.

use nonos_app_skeleton::PaintBuffer;
use nonos_toolkit::theme::roles;

use crate::about::data::attest_doc::Attestation;

use super::super::card::{self, titled};
use super::super::kv::ROW_H;
use super::super::metrics::{BODY_PX, CARD_PAD, PAIR_H};
use super::super::text::{line, top_of};

const ROWS: u32 = 4;

pub const HEIGHT: u32 = card::OVERHEAD + ROW_H + PAIR_H + ROW_H * ROWS + 4;

pub fn paint(fb: &mut PaintBuffer, y: i32, w: u32, att: &Attestation) {
    let inner = card::inner(w);
    let top = titled(fb, 0, y, w, HEIGHT, b"Signed by the hardware");
    match att {
        Attestation::Produced(doc) => super::verify_doc_body::body(fb, top, inner, doc),
        Attestation::Refused => {
            note(fb, top, b"This machine declined to attest. It has no trusted platform module, or it could not record everything it is running.");
        }
        Attestation::Malformed => {
            note(fb, top, b"A document came back that did not parse. That is a fault, not an absence, and nothing below it is claimed.");
        }
        Attestation::NotAsked => note(fb, top, b"Not asked."),
    }
}

fn note(fb: &mut PaintBuffer, top: i32, msg: &[u8]) {
    let r = roles();
    line(fb, CARD_PAD, top_of(top, ROW_H, BODY_PX), msg, r.muted.argb(), BODY_PX);
}
