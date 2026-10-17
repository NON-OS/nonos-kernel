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

//! What the kernel found when it checked the bootloader that started it.
//!
//! The card above is the bootloader's word about the kernel; this one is the
//! kernel's word about the bootloader. Both were settled once, at boot, and
//! the subtitle says so for the same reason the card above does.

use nonos_app_skeleton::PaintBuffer;
use nonos_toolkit::theme::roles;
use nonos_toolkit::widgets::text::{centre_top, left};

use crate::about::data::verify::{loader, Loader};
use crate::about::format::u64_decimal;
use crate::about::format_hex::hex_bytes;

use super::super::card::{self, titled};
use super::super::kv::{pair, ROW_H};
use super::super::metrics::{BODY_PX, CARD_PAD, PAIR_H};
use super::append::put;
use super::verify_boot::HASH_GAP;
use super::verify_row::row;

pub const HEIGHT: u32 = card::OVERHEAD + ROW_H * 2 + HASH_GAP + PAIR_H * 2;

pub fn paint(fb: &mut PaintBuffer, y: i32, w: u32) {
    let muted = roles().muted;
    let inner = card::inner(w);
    let top = titled(fb, 0, y, w, HEIGHT, b"Checked by the kernel at boot");
    let note = "The kernel's check of its bootloader. Reading it here does not re-check it.";
    left(fb, CARD_PAD, top + centre_top(0, ROW_H, BODY_PX), note, muted, BODY_PX);
    let l = loader();
    let mut ev = [0u8; 32];
    row(fb, CARD_PAD, top + ROW_H as i32, inner, l.verdict, l.claim, evidence(&l, &mut ev));

    /*
     * Shown in full, like the boot record's digests: these are what a reader
     * compares against the release that enrolled the loader.
     */
    let hash_y = top + (ROW_H * 2 + HASH_GAP) as i32;
    let (mut m, mut r) = ([0u8; 64], [0u8; 64]);
    let (measured, root): (&[u8], &[u8]) = match &l.admitted {
        Some(a) => (hex_bytes(&a.measurement, &mut m), hex_bytes(&a.root, &mut r)),
        None => (b"nothing admitted", b"nothing admitted"),
    };
    pair(fb, CARD_PAD, hash_y, inner, b"Bootloader Authenticode SHA-256", measured, true);
    pair(fb, CARD_PAD, hash_y + PAIR_H as i32, inner, b"Boot root", root, true);
}

/* "epoch 3" for an admitted loader, "code 403" for a refused one. */
fn evidence<'a>(l: &Loader, buf: &'a mut [u8; 32]) -> &'a [u8] {
    let (label, value): (&[u8], u64) = match (l.admitted, l.code) {
        (Some(a), _) => (b"epoch ", a.epoch),
        (None, Some(c)) => (b"code ", u64::from(c)),
        (None, None) => return b"",
    };
    let mut digits = [0u8; 20];
    let mut n = put(&mut buf[..], label);
    n += put(&mut buf[n..], u64_decimal(value, &mut digits));
    &buf[..n]
}
