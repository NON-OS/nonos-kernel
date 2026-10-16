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

//! The claims this capsule tested itself, a moment ago, against the live kernel.

use nonos_app_skeleton::PaintBuffer;
use nonos_toolkit::theme::roles;

use crate::about::data::verify::{live, Live};

use super::super::card::{self, titled};
use super::super::kv::ROW_H;
use super::super::metrics::{BODY_PX, CARD_PAD};
use super::super::text::{line, top_of};
use super::verify_census::{census, CENSUS_ROWS};
use super::verify_evidence::evidence;
use super::verify_row::row;

const CHECKS: u32 = 4;
const GROUP_GAP: u32 = 14;

pub const HEIGHT: u32 =
    card::OVERHEAD + ROW_H * CHECKS + GROUP_GAP + ROW_H + ROW_H * CENSUS_ROWS + 4;

pub fn paint(fb: &mut PaintBuffer, y: i32, w: u32) {
    let r = roles();
    let inner = card::inner(w);
    let top = titled(fb, 0, y, w, HEIGHT, b"Checked now");
    match live() {
        Some(l) => body(fb, top, inner, &l),
        /*
         * The kernel refusing the process table is itself a fact, and one that
         * must not read as four quiet passes.
         */
        None => {
            let msg = b"the kernel did not answer, so nothing below is claimed";
            line(fb, CARD_PAD, top_of(top, ROW_H, BODY_PX), msg, r.muted.argb(), BODY_PX);
        }
    }
}

fn body(fb: &mut PaintBuffer, top: i32, inner: u32, l: &Live) {
    let r = roles();
    for (i, c) in l.checks.iter().enumerate() {
        let mut buf = [0u8; 32];
        row(
            fb,
            CARD_PAD,
            top + (i as u32 * ROW_H) as i32,
            inner,
            c.verdict,
            c.claim,
            evidence(c, &mut buf),
        );
    }

    let census_y = top + (ROW_H * CHECKS + GROUP_GAP) as i32;
    let head = b"Counted, not tested. Nothing here can be wrong.";
    line(fb, CARD_PAD, top_of(census_y, ROW_H, BODY_PX), head, r.muted.argb(), BODY_PX);
    census(fb, census_y + ROW_H as i32, inner, &l.census);
}
