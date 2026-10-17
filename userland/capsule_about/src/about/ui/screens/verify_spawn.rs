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

//! The capsules running now that the kernel proved before it started them.
//!
//! Read from the attestation registry each time the screen is drawn: the
//! entries the signed document's root folds. Each was admitted only after the
//! kernel checked its STARK proof at spawn, except one a publisher only
//! signed, which gets a dash and says so.

use nonos_app_skeleton::PaintBuffer;
use nonos_toolkit::theme::roles;
use nonos_toolkit::widgets::text::{centre_top, left};

use crate::about::data::verify::Attested;

use super::super::card::{self, titled};
use super::super::kv::ROW_H;
use super::super::metrics::{BODY_PX, CARD_PAD};
use super::super::mono::valid;
use super::verify_spawn_row::row;

pub fn height(list: Option<&[Attested]>) -> u32 {
    let rows = list.map_or(1, |l| l.len().max(1)) as u32;
    card::OVERHEAD + ROW_H + ROW_H * rows + 4
}

pub fn paint(fb: &mut PaintBuffer, y: i32, w: u32, list: Option<&[Attested]>) {
    let r = roles();
    let inner = card::inner(w);
    let top = titled(fb, 0, y, w, height(list), b"Proved at spawn");
    let note = "Running now. Each row says whether a STARK proof or a signature admitted it.";
    left(fb, CARD_PAD, top + centre_top(0, ROW_H, BODY_PX), note, r.muted, BODY_PX);
    let first = top + ROW_H as i32;
    let msg: &[u8] = match list {
        Some(l) if !l.is_empty() => {
            for (i, a) in l.iter().enumerate() {
                row(fb, CARD_PAD, first + (i as u32 * ROW_H) as i32, inner, a);
            }
            return;
        }
        Some(_) => b"the registry lists no running capsule",
        /* A refusal is not an empty registry, and must not read as one. */
        None => b"the kernel did not list them: reading the registry needs AttestRead",
    };
    left(fb, CARD_PAD, first + centre_top(0, ROW_H, BODY_PX), valid(msg), r.muted, BODY_PX);
}
