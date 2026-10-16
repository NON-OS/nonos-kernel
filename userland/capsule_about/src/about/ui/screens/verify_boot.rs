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

//! What the bootloader established before the kernel existed, read back.
//!
//! The kernel's own syscall is explicit that it re-verifies none of this: it
//! hands back the record the bootloader wrote into the handoff. So the card says
//! so in its own subtitle. A reader who mistakes this for a live check would draw
//! a stronger conclusion than the evidence supports, and the entire value of this
//! screen is that it does not let them.

use nonos_app_skeleton::PaintBuffer;
use nonos_toolkit::theme::roles;

use crate::about::data::verify::recorded;

use super::super::card::{self, titled};
use super::super::kv::ROW_H;
use super::super::metrics::{BODY_PX, CARD_PAD, PAIR_H};
use super::super::text::{line, top_of};

pub(super) const CLAIMS: u32 = 4;
pub(super) const HASH_GAP: u32 = 12;

pub const HEIGHT: u32 = card::OVERHEAD + ROW_H + ROW_H * CLAIMS + HASH_GAP + PAIR_H * 2;

// Wording is deliberately past tense throughout: each of these was settled once,
// at a moment that has gone, by a component that is no longer running.
pub(super) const CLAIM_TEXT: [&[u8]; CLAIMS as usize] = [
    b"kernel image signature verified",
    b"UEFI Secure Boot was on",
    b"attestation accepted",
    b"proof verified",
];

pub fn paint(fb: &mut PaintBuffer, y: i32, w: u32) {
    let muted = roles().muted.argb();
    let inner = card::inner(w);
    let top = titled(fb, 0, y, w, HEIGHT, b"Recorded at boot");
    let note = b"Measured by the bootloader. Reading it here does not re-check it.";
    line(fb, CARD_PAD, top_of(top, ROW_H, BODY_PX), note, muted, BODY_PX);
    let first = top + ROW_H as i32;
    match recorded() {
        Some(r) => super::verify_boot_body::body(fb, first, inner, &r),
        None => {
            let msg = b"the kernel returned no boot record";
            line(fb, CARD_PAD, top_of(first, ROW_H, BODY_PX), msg, muted, BODY_PX);
        }
    }
}
